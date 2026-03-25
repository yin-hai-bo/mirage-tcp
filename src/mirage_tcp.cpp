#include "mirage_tcp/mirage_tcp.hpp"

#include "checksum.h"
#include "connection_info.hpp"
#include "ip6_head.h"
#include "ipv4_packet.h"
#include "tcp_head.h"
#include "tcp_segment.h"
#include "packet_buffer_pool.h"

#include <cassert>
#include <cstring>
#include <type_traits>
#include <unordered_map>

namespace mirage_tcp {

namespace {

void write_u16_be(uint16_t value, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[1] = static_cast<uint8_t>(value & 0xff);
}

struct TcpIpv4PseudoHeader {
    uint32_t source_address;
    uint32_t destination_address;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;

    /**
     * @brief Builds one IPv4 TCP pseudo-header in network byte order.
     *
     * @param source_address_value Source IPv4 address.
     * @param destination_address_value Destination IPv4 address.
     * @param tcp_length_host_order TCP segment length in host byte order.
     */
    TcpIpv4PseudoHeader(
        const in_addr& source_address_value,
        const in_addr& destination_address_value,
        uint16_t tcp_length_host_order)
        : source_address(source_address_value.s_addr),
          destination_address(destination_address_value.s_addr),
          zero(0),
          protocol(IP_PROTOCOL_TCP),
          tcp_length(htons(tcp_length_host_order)) {}
};

static_assert(sizeof(TcpIpv4PseudoHeader) == 12, "TcpIpv4PseudoHeader must match the IPv4 TCP pseudo-header size");
static_assert(std::is_standard_layout<TcpIpv4PseudoHeader>::value, "TcpIpv4PseudoHeader must be standard-layout");
static_assert(std::is_trivially_copyable<TcpIpv4PseudoHeader>::value, "TcpIpv4PseudoHeader must be trivially copyable");

size_t serialized_tcp_segment_size(size_t payload_size) {
    return sizeof(TcpHead) + payload_size;
}

void serialize_tcp_segment_with_checksum(
    const ConnectionInfo& connection_info,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    uint8_t flags,
    const void* payload,
    size_t payload_size,
    uint8_t* target)
{
    const size_t tcp_size = serialized_tcp_segment_size(payload_size);
    TcpHead head = {};
    head.source_port = htons(connection_info.server_port);
    head.destination_port = htons(connection_info.client_port);
    head.sequence_number = htonl(sequence_number);
    head.acknowledgment_number = htonl(acknowledgment_number);
    head.data_offset_reserved = static_cast<uint8_t>(5U << 4);
    head.flags = flags;
    head.window_size = htons(65535);
    head.checksum = 0;
    head.urgent_pointer = 0;
    std::memcpy(target, &head, sizeof(head));

    if (payload && payload_size > 0) {
        std::memcpy(target + sizeof(TcpHead), payload, payload_size);
    }

    const TcpIpv4PseudoHeader pseudo_header(
        connection_info.server_ip.ipv4,
        connection_info.client_ip.ipv4,
        static_cast<uint16_t>(tcp_size));

    const uint16_t pseudo_header_sum = Checksum::Calculate(&pseudo_header, sizeof(pseudo_header));
    const uint16_t checksum = static_cast<uint16_t>(~Checksum::Calculate(target, tcp_size, pseudo_header_sum));
    write_u16_be(checksum, target + offsetof(TcpHead, checksum));
}

mirage_tcp_error_code_t parse_ipv6_tcp_packet(const void* packet, size_t packet_size) {
    if (packet == nullptr) {
        return MTE_InvalidArgument;
    }

    if (packet_size == 0) {
        return MTE_InvalidArgument;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(packet);
    const uint8_t version = static_cast<uint8_t>(bytes[0] >> 4);
    if (version != Ip6Head::VERSION) {
        return MTE_UnsupportedIpVersion;
    }

    return MTE_Unsupported;
}

}  // namespace

class MirageTcp::Impl {
public:
    Impl(const mirage_tcp_callbacks_t & callbacks)
        : callbacks_(callbacks)
    {}

    /**
     * @brief Accepts one inbound IP packet from the host.
     *
     * @param ip_packet Pointer to raw IP packet bytes. The caller guarantees
     *        that @p ip_packet is not null and is aligned to alignof(Ip6Head).
     * @param ip_packet_size Size of @p ip_packet in bytes.
     * @return 0 if the packet is accepted; otherwise an error code.
     */
    mirage_tcp_error_code_t handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size) {
        if (ip_packet == nullptr) {
            return MTE_InvalidArgument;
        }
        assert(reinterpret_cast<std::uintptr_t>(ip_packet) % alignof(Ip6Head) == 0U);

        Ip4PacketView ipv4_packet;
        const mirage_tcp_error_code_t ipv4_parse_result = parse_ipv4_tcp_packet(ip_packet, ip_packet_size, ipv4_packet);
        if (ipv4_parse_result == MTE_Ok) {
            return handle_incoming_ip4_tcp_packet(ipv4_packet);
        }

        if (ipv4_parse_result == MTE_UnsupportedIpVersion) {
            return parse_ipv6_tcp_packet(ip_packet, ip_packet_size);
        }
        return ipv4_parse_result;
    }

    mirage_tcp_error_code_t send_downstream_tcp_payload(
        const ConnectionInfo& connection_info,
        const void* payload,
        size_t payload_size)
    {
        if (payload == nullptr || payload_size == 0) {
            return MTE_PayloadEmpty;
        }

        if (connection_info.ip_ver != 4) {
            return MTE_Ipv4OnlyOperation;
        }

        FlowMap::iterator it = ipv4_flows_.find(connection_info);
        if (it == ipv4_flows_.end()) {
            return MTE_FlowNotFound;
        }

        if (it->second.state != FlowState::Established) {
            return MTE_SendBeforeEstablished;
        }

        Flow* const flow = &it->second;
        const mirage_tcp_error_code_t emit_result = emit_tcp_response(
                flow->connection_info,
                flow->server_next_sequence,
                flow->client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().flags(),
                payload,
                payload_size);
        if (emit_result != MTE_Ok) {
            return emit_result;
        }
        flow->server_next_sequence += static_cast<uint32_t>(payload_size);
        return MTE_Ok;
    }

    mirage_tcp_error_code_t close_flow(const ConnectionInfo& connection_info) {
        if (connection_info.ip_ver != 4) {
            return MTE_Ipv4OnlyOperation;
        }

        FlowMap::iterator it = ipv4_flows_.find(connection_info);
        if (it == ipv4_flows_.end()) {
            return MTE_FlowNotFound;
        }

        if (it->second.state != FlowState::Established) {
            return MTE_CloseBeforeEstablished;
        }

        Flow& flow = it->second;
        const mirage_tcp_error_code_t emit_result = emit_tcp_response(
                flow.connection_info,
                flow.server_next_sequence,
                flow.client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().set_fin().flags());
        if (emit_result != MTE_Ok) {
            return emit_result;
        }
        flow.server_next_sequence += 1;
        flow.state = FlowState::LastAck;
        return MTE_Ok;
    }


private:
    enum class FlowState {
        SynReceived,
        Established,
        LastAck
    };

    struct Flow {
        const ConnectionInfo connection_info;
        FlowState state;
        uint32_t client_next_sequence;
        uint32_t server_next_sequence;

        Flow(
            const ConnectionInfo& flow_connection_info,
            FlowState flow_state,
            uint32_t client_next_sequence_value,
            uint32_t server_next_sequence_value)
            : connection_info(flow_connection_info),
              state(flow_state),
              client_next_sequence(client_next_sequence_value),
              server_next_sequence(server_next_sequence_value) {}
    };

    using FlowMap = std::unordered_map<ConnectionInfo, Flow, ConnectionInfoHash, ConnectionInfoEqual>;

    mirage_tcp_error_code_t handle_incoming_ip4_tcp_packet(const Ip4PacketView & ipv4_packet) {
        TcpSegment tcp_segment;
        const mirage_tcp_error_code_t tcp_parse_result = parse_tcp_segment(ipv4_packet.payload, ipv4_packet.payload_size, tcp_segment);
        if (tcp_parse_result != MTE_Ok) {
            return tcp_parse_result;
        }

        ConnectionInfo key;
        mirage_tcp_set_connection_info_v4(
            &ipv4_packet.source_address,
            &ipv4_packet.destination_address,
            tcp_segment.source_port,
            tcp_segment.destination_port,
            &key);

        if (tcp_segment.is_syn() && !tcp_segment.is_ack()) {
            return handle_syn(key, tcp_segment.sequence_number);
        }

        FlowMap::iterator it = ipv4_flows_.find(key);
        if (it == ipv4_flows_.end()) {
            if (tcp_segment.is_rst()) {
                return MTE_Ok;
            }
            emit_reset_for_unhandled_packet(
                key,
                tcp_segment);
            return MTE_FlowNotFound;
        }

        Flow& flow = it->second;
        if (tcp_segment.is_rst()) {
            const ConnectionInfo reset_flow = flow.connection_info;
            ipv4_flows_.erase(it);
            emit_reset(reset_flow);
            return MTE_Ok;
        }

        if (flow.state == FlowState::SynReceived) {
            if (!tcp_segment.is_ack() || tcp_segment.acknowledgment_number != flow.server_next_sequence) {
                return fail_flow(
                    flow.connection_info,
                    MTE_HandshakeFinalAckExpected,
                    tcp_segment);
            }

            if (tcp_segment.sequence_number != flow.client_next_sequence) {
                return fail_flow(
                    flow.connection_info,
                    MTE_HandshakeClientSequenceUnexpected,
                    tcp_segment);
            }

            flow.state = FlowState::Established;
            const auto cb = callbacks_.on_tcp_handshake_completed;
            if (cb) {
                cb(callbacks_.user_data, &flow.connection_info);
            }
            if (tcp_segment.payload.empty() && !tcp_segment.is_fin()) {
                return MTE_Ok;
            }
            return handle_established_packet(
                flow,
                tcp_segment);
        }

        if (flow.state == FlowState::Established) {
            return handle_established_packet(
                flow,
                tcp_segment);
        }

        return handle_last_ack_packet(flow, tcp_segment);
    }

    void emit_downstream_ip_packet(const void* ip_packet, size_t ip_packet_size) const {
        const auto cb = callbacks_.on_downstream_ip_packet_generated;
        if (cb) {
            cb(callbacks_.user_data, ip_packet, ip_packet_size);
        }
    }

    void emit_reset(const ConnectionInfo & connection_info) const {
        const auto cb = callbacks_.on_tcp_connection_reset;
        if (cb) {
            cb(callbacks_.user_data, &connection_info);
        }
    }

    mirage_tcp_error_code_t handle_syn(const ConnectionInfo& connection_info, uint32_t client_sequence) {
        const uint32_t client_next_sequence = client_sequence + 1;
        // Keep the server ISN deterministic so packet-level tests can assert
        // exact sequence behavior without relying on a random source.
        const uint32_t server_sequence_for_syn_ack = 7000 + static_cast<uint32_t>(ipv4_flows_.size()) * 1024U;
        const uint32_t server_next_sequence = server_sequence_for_syn_ack + 1;
        const Flow flow(
            connection_info,
            FlowState::SynReceived,
            client_next_sequence,
            server_next_sequence);

        const auto inserted =
            ipv4_flows_.insert(std::make_pair(connection_info, flow));
        if (!inserted.second) {
            return MTE_FlowAlreadyExists;
        }

        const mirage_tcp_error_code_t emit_result = emit_tcp_response(
                connection_info,
                server_sequence_for_syn_ack,
                client_next_sequence,
                TcpSegment::FlagsBuilder().set_syn().set_ack().flags());
        if (emit_result != MTE_Ok) {
            ipv4_flows_.erase(connection_info);
            return emit_result;
        }

        return MTE_Ok;
    }

    mirage_tcp_error_code_t handle_established_packet(
        Flow& flow,
        const TcpSegment& segment) {
        if (segment.is_rst()) {
            const ConnectionInfo reset_flow = flow.connection_info;
            ipv4_flows_.erase(reset_flow);
            emit_reset(reset_flow);
            return MTE_Ok;
        }

        if (!segment.is_ack()) {
            return fail_flow(
                flow.connection_info,
                MTE_EstablishedAckRequired,
                segment);
        }

        if (segment.acknowledgment_number != flow.server_next_sequence) {
            return fail_flow(
                flow.connection_info,
                MTE_EstablishedAckNumberUnexpected,
                segment);
        }

        if (segment.sequence_number != flow.client_next_sequence) {
            return fail_flow(
                flow.connection_info,
                MTE_EstablishedSequenceUnexpected,
                segment);
        }

        const bool has_payload = !segment.payload.empty();
        const bool has_fin = segment.is_fin();

        if (has_payload) {
            flow.client_next_sequence += static_cast<uint32_t>(segment.payload.size());
            const auto cb = callbacks_.on_tcp_payload_received;
            if (cb) {
                cb(
                    callbacks_.user_data,
                    &flow.connection_info,
                    &segment.payload[0],
                    segment.payload.size());
            }
        }

        if (has_fin) {
            flow.client_next_sequence += 1;
            flow.state = FlowState::LastAck;
            const mirage_tcp_error_code_t emit_result = emit_tcp_response(
                    flow.connection_info,
                    flow.server_next_sequence,
                    flow.client_next_sequence,
                    TcpSegment::FlagsBuilder().set_ack().set_fin().flags());
            if (emit_result != MTE_Ok) {
                return emit_result;
            }
            flow.server_next_sequence += 1;
            return MTE_Ok;
        }

        if (has_payload) {
            return emit_tcp_response(
                flow.connection_info,
                flow.server_next_sequence,
                flow.client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().flags());
        }

        return MTE_Ok;
    }

    mirage_tcp_error_code_t handle_last_ack_packet(const Flow& flow, const TcpSegment& segment) {
        if (!segment.is_ack()) {
            return fail_flow(
                flow.connection_info,
                MTE_CloseFinalAckExpected,
                segment);
        }

        if (segment.acknowledgment_number != flow.server_next_sequence) {
            return fail_flow(
                flow.connection_info,
                MTE_CloseAckUnexpected,
                segment);
        }

        if (segment.sequence_number != flow.client_next_sequence) {
            return fail_flow(
                flow.connection_info,
                MTE_CloseSequenceUnexpected,
                segment);
        }

        const ConnectionInfo completed_flow = flow.connection_info;
        ipv4_flows_.erase(completed_flow);
        const auto cb = callbacks_.on_tcp_connection_closed;
        if (cb) {
            cb(callbacks_.user_data, &completed_flow);
        }
        return MTE_Ok;
    }

    mirage_tcp_error_code_t emit_reset_for_unhandled_packet(
        const ConnectionInfo& connection_info,
        const TcpSegment& segment) {
        if (segment.flags & TcpSegment::BITS_MASK_ACK) {
            return emit_tcp_response(
                connection_info,
                segment.acknowledgment_number,
                0,
                TcpSegment::FlagsBuilder().set_rst().flags());
        }

        uint32_t ack_number =
            segment.sequence_number + static_cast<uint32_t>(segment.payload.size());
        if (segment.flags & TcpSegment::BITS_MASK_SYN) {
            ++ack_number;
        }
        if (segment.flags & TcpSegment::BITS_MASK_FIN) {
            ++ack_number;
        }
        return emit_tcp_response(
            connection_info,
            0,
            ack_number,
            TcpSegment::FlagsBuilder().set_ack().set_rst().flags());
    }

    mirage_tcp_error_code_t fail_flow(
        const ConnectionInfo& connection_info,
        mirage_tcp_error_code_t error_code,
        const TcpSegment& segment) {
        ipv4_flows_.erase(connection_info);
        emit_reset_for_unhandled_packet(
            connection_info,
            segment);
        emit_reset(connection_info);
        return error_code;
    }

    mirage_tcp_error_code_t emit_tcp_response(
        const ConnectionInfo & connection_info,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        uint8_t flags)
    {
        return emit_tcp_response(connection_info, sequence_number, acknowledgment_number, flags, nullptr, 0);
    }

    mirage_tcp_error_code_t emit_tcp_response(
        const ConnectionInfo& connection_info,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        uint8_t flags,
        const void* payload,
        size_t payload_size
    ) {
        const size_t ipv4_header_size = sizeof(Ip4Head);
        const size_t tcp_size = serialized_tcp_segment_size(payload_size);
        const size_t packet_size = ipv4_header_size + tcp_size;
        if (packet_size > PacketBufferPool::BUFFER_CAPACITY) {
            return MTE_PacketEmitFailed;
        }

        PacketBufferLease packet_buffer(packet_buffer_pool_);
        uint8_t* const packet_bytes = packet_buffer.data();
        if (packet_bytes == nullptr) {
            return MTE_PacketEmitFailed;
        }

        Ip4Head head = {};
        head.version_ihl = 0x45;
        head.total_length = htons(static_cast<uint16_t>(packet_size));
        head.ttl = 64;
        head.protocol = IP_PROTOCOL_TCP;
        std::memcpy(&head.source_address, &connection_info.server_ip.ipv4, sizeof(head.source_address));
        std::memcpy(&head.destination_address, &connection_info.client_ip.ipv4, sizeof(head.destination_address));
        head.header_checksum = 0;
        head.header_checksum = htons(static_cast<uint16_t>(~Checksum::Calculate(&head, sizeof(head))));

        std::memcpy(packet_bytes, &head, sizeof(head));
        serialize_tcp_segment_with_checksum(
            connection_info,
            sequence_number,
            acknowledgment_number,
            flags,
            payload,
            payload_size,
            packet_bytes + ipv4_header_size);

        emit_downstream_ip_packet(packet_bytes, packet_size);
        return MTE_Ok;
    }

private:
    mirage_tcp_callbacks_t callbacks_;
    FlowMap ipv4_flows_;
    PacketBufferPool packet_buffer_pool_;
};

MirageTcp::MirageTcp(const mirage_tcp_callbacks_t & callbacks)
    : impl_(new Impl(callbacks))
{}

 MirageTcp::MirageTcp(MirageTcp &&) = default;

 MirageTcp & MirageTcp::operator=(MirageTcp &&) = default;

MirageTcp::~MirageTcp() = default;

mirage_tcp_error_code_t MirageTcp::handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size) {
    return impl_->handle_incoming_ip_packet(ip_packet, ip_packet_size);
}

mirage_tcp_error_code_t MirageTcp::send_downstream_tcp_payload(
    const ConnectionInfo& connection_info,
    const void* payload,
    size_t payload_size)
{
    return impl_->send_downstream_tcp_payload(connection_info, payload, payload_size);
}

mirage_tcp_error_code_t MirageTcp::close_flow(const ConnectionInfo& connection_info) {
    return impl_->close_flow(connection_info);
}

}  // namespace mirage_tcp

extern "C" {

mirage_tcp_error_code_t mirage_tcp_create(mirage_tcp_callbacks_t const * callbacks, mirage_tcp_object * result) {
    if (!callbacks || !result) {
        return MTE_InvalidArgument;
    }
    *result = nullptr;
    try {
        auto const instance = new mirage_tcp::MirageTcp(*callbacks);
        *result = reinterpret_cast<mirage_tcp_object>(instance);
        return MTE_Ok;
    } catch (const std::bad_alloc &) {
        return MTE_OutOfMemory;
    }
}

 void mirage_tcp_destroy(mirage_tcp_object instance) {
    delete reinterpret_cast<mirage_tcp::MirageTcp *>(instance);
}

mirage_tcp_error_code_t mirage_tcp_handle_incoming_ip_packet(
    mirage_tcp_object instance,
    const void * ip_packet,
    size_t ip_packet_size)         
{
    if (instance == nullptr) {
        return MTE_InvalidArgument;
    }
    return reinterpret_cast<mirage_tcp::MirageTcp *>(instance)
        ->handle_incoming_ip_packet(ip_packet, ip_packet_size);
}

mirage_tcp_error_code_t mirage_tcp_send_downstream_tcp_payload(
    mirage_tcp_object instance,
    const mirage_tcp_connection_info_t * connection_info,
    const void * payload,
    size_t payload_size)         
{
    if (instance == nullptr || connection_info == nullptr) {
        return MTE_InvalidArgument;
    }
    return reinterpret_cast<mirage_tcp::MirageTcp *>(instance)
        ->send_downstream_tcp_payload(
            *connection_info,
            payload,
            payload_size);
}

mirage_tcp_error_code_t mirage_tcp_close_flow(
    mirage_tcp_object instance,
    const mirage_tcp_connection_info_t * connection_info)
{
    if (instance == nullptr || connection_info == nullptr) {
        return MTE_InvalidArgument;
    }
    return reinterpret_cast<mirage_tcp::MirageTcp *>(instance)
        ->close_flow(*connection_info);
}

}
