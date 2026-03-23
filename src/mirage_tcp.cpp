#include "mirage_tcp/checksum.h"
#include "mirage_tcp/mirage_tcp.h"
#include "mirage_tcp/ipv4_packet.h"
#include "mirage_tcp/tcp_segment.h"
#include "ipv4_packet_internal.h"

#include <cassert>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace mirage_tcp {

namespace {

ConnectionInfo::Address make_ipv4_address_storage(const in_addr& address) {
    ConnectionInfo::Address value = {};
    value.ipv4 = address;
    return value;
}

ConnectionInfo::Address make_ipv6_address_storage(const in6_addr& address) {
    ConnectionInfo::Address value = {};
    value.ipv6 = address;
    return value;
}

void write_u16_be(uint16_t value, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[1] = static_cast<uint8_t>(value & 0xff);
}

std::vector<uint8_t> serialize_tcp_segment_with_checksum(
    const ConnectionInfo& connection_info,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    uint8_t flags,
    const void* payload,
    size_t payload_size) {
    TcpSegment segment;
    segment.source_port = connection_info.server_port;
    segment.destination_port = connection_info.client_port;
    segment.sequence_number = sequence_number;
    segment.acknowledgment_number = acknowledgment_number;
    segment.window_size = 65535;
    segment.flags = flags;
    if (payload != NULL && payload_size > 0) {
        const uint8_t* payload_bytes = static_cast<const uint8_t*>(payload);
        segment.payload.assign(payload_bytes, payload_bytes + static_cast<std::ptrdiff_t>(payload_size));
    }

    std::vector<uint8_t> bytes = serialize_tcp_segment(segment);
    std::vector<uint8_t> pseudo_header(12 + bytes.size() + (bytes.size() % 2U), 0);
    std::memcpy(&pseudo_header[0], &connection_info.server_ip.ipv4, 4);
    std::memcpy(&pseudo_header[4], &connection_info.client_ip.ipv4, 4);
    pseudo_header[9] = 6;
    write_u16_be(static_cast<uint16_t>(bytes.size()), &pseudo_header[10]);
    for (size_t i = 0; i < bytes.size(); ++i) {
        pseudo_header[12 + i] = bytes[i];
    }

    write_u16_be(0, &bytes[16]);
    const uint16_t checksum = ~Checksum::Calculate(&pseudo_header[0], pseudo_header.size());
    write_u16_be(checksum, &bytes[16]);
    return bytes;
}

error_code_t parse_ipv6_tcp_packet(const void* packet, size_t packet_size) {
    if (packet == NULL) {
        return ErrorCode::InvalidArgument;
    }

    if (packet_size == 0) {
        return ErrorCode::InvalidArgument;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(packet);
    const uint8_t version = static_cast<uint8_t>(bytes[0] >> 4);
    if (version != 6) {
        return ErrorCode::UnsupportedIpVersion;
    }

    return ErrorCode::Unsupported;
}

}  // namespace

ConnectionInfo::ConnectionInfo(
    const in_addr& client_ipv4,
    const in_addr& server_ipv4,
    uint16_t client_port_value,
    uint16_t server_port_value)
    : client_ip(make_ipv4_address_storage(client_ipv4)),
      server_ip(make_ipv4_address_storage(server_ipv4)),
      client_port(client_port_value),
      server_port(server_port_value),
      ip_ver(4) {}

ConnectionInfo::ConnectionInfo(
    const in6_addr& client_ipv6,
    const in6_addr& server_ipv6,
    uint16_t client_port_value,
    uint16_t server_port_value)
    : client_ip(make_ipv6_address_storage(client_ipv6)),
      server_ip(make_ipv6_address_storage(server_ipv6)),
      client_port(client_port_value),
      server_port(server_port_value),
      ip_ver(6) {}

bool operator<(const ConnectionInfo& left, const ConnectionInfo& right) {
    if (left.ip_ver != right.ip_ver) {
        return left.ip_ver < right.ip_ver;
    }

    if (left.client_port != right.client_port) {
        return left.client_port < right.client_port;
    }

    if (left.server_port != right.server_port) {
        return left.server_port < right.server_port;
    }

    if (left.ip_ver == 4) {
        if (left.client_ip.ipv4.s_addr != right.client_ip.ipv4.s_addr) {
            return left.client_ip.ipv4.s_addr < right.client_ip.ipv4.s_addr;
        }

        return left.server_ip.ipv4.s_addr < right.server_ip.ipv4.s_addr;
    }

    const int client_compare =
        std::memcmp(&left.client_ip.ipv6, &right.client_ip.ipv6, sizeof(left.client_ip.ipv6));
    if (client_compare != 0) {
        return client_compare < 0;
    }

    return std::memcmp(&left.server_ip.ipv6, &right.server_ip.ipv6, sizeof(left.server_ip.ipv6)) < 0;
}

bool operator==(const ConnectionInfo& left, const ConnectionInfo& right) {
    return ConnectionInfoEqual()(left, right);
}

size_t ConnectionInfoHash::operator()(const ConnectionInfo& connection_info) const {
    const uint32_t ports =
        (static_cast<uint32_t>(connection_info.client_port) << 16) |
        static_cast<uint32_t>(connection_info.server_port);
    uint32_t hash = ports ^ static_cast<uint32_t>(connection_info.ip_ver);

    if (connection_info.ip_ver == 4) {
        hash ^= connection_info.client_ip.ipv4.s_addr;
        hash ^= connection_info.server_ip.ipv4.s_addr;
    } else {
        // We normalize into aligned uint32_t words because some supported
        // platforms expose in6_addr with insufficient alignment for direct
        // uint32_t pointer access.
        uint32_t words[8] = {};
        std::memcpy(&words[0], &connection_info.client_ip.ipv6, sizeof(connection_info.client_ip.ipv6));
        std::memcpy(&words[4], &connection_info.server_ip.ipv6, sizeof(connection_info.server_ip.ipv6));
        for (size_t i = 0; i < 8; ++i) {
            hash ^= words[i];
        }
    }
    return static_cast<size_t>(hash);
}

bool ConnectionInfoEqual::operator()(const ConnectionInfo& left, const ConnectionInfo& right) const {
    if (left.ip_ver != right.ip_ver) {
        return false;
    }

    if (left.client_port != right.client_port) {
        return false;
    }

    if (left.server_port != right.server_port) {
        return false;
    }

    if (left.ip_ver == 4) {
        return left.client_ip.ipv4.s_addr == right.client_ip.ipv4.s_addr &&
               left.server_ip.ipv4.s_addr == right.server_ip.ipv4.s_addr;
    }

    return std::memcmp(&left.client_ip.ipv6, &right.client_ip.ipv6, sizeof(left.client_ip.ipv6)) == 0 &&
           std::memcmp(&left.server_ip.ipv6, &right.server_ip.ipv6, sizeof(left.server_ip.ipv6)) == 0;
}

MirageTcpCallbacks::MirageTcpCallbacks()
    : user_data(NULL),
      on_downstream_ip_packet_generated(NULL),
      on_tcp_handshake_completed(NULL),
      on_tcp_payload_received(NULL),
      on_tcp_connection_closed(NULL),
      on_tcp_connection_reset(NULL),
      on_error(NULL) {}

class MirageTcp::Impl {
public:
    Impl(const MirageTcpCallbacks& callbacks)
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
    error_code_t handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size) {
        if (ip_packet == nullptr) {
            return ErrorCode::InvalidArgument;
        }
        assert(reinterpret_cast<std::uintptr_t>(ip_packet) % alignof(Ip6Head) == 0U);

        Ip4PacketView ipv4_packet;
        const error_code_t ipv4_parse_result = parse_ipv4_tcp_packet(ip_packet, ip_packet_size, ipv4_packet);
        if (ipv4_parse_result == ErrorCode::Ok) {
            return handle_incoming_ip4_tcp_packet(ipv4_packet);
        }

        if (ipv4_parse_result == ErrorCode::UnsupportedIpVersion) {
            return parse_ipv6_tcp_packet(ip_packet, ip_packet_size);
        }
        return ipv4_parse_result;
    }

    error_code_t send_downstream_tcp_payload(
        const ConnectionInfo& connection_info,
        const void* payload,
        size_t payload_size)
    {
        if (payload == nullptr || payload_size == 0) {
            emit_error(ErrorCode::PayloadEmpty);
            return ErrorCode::PayloadEmpty;
        }

        if (connection_info.ip_ver != 4) {
            emit_error(ErrorCode::Ipv4OnlyOperation);
            return ErrorCode::Ipv4OnlyOperation;
        }

        FlowMap::iterator it = ipv4_flows_.find(connection_info);
        if (it == ipv4_flows_.end()) {
            emit_error(ErrorCode::FlowNotFound);
            return ErrorCode::FlowNotFound;
        }

        if (it->second.state != FlowState::Established) {
            emit_error(ErrorCode::SendBeforeEstablished);
            return ErrorCode::SendBeforeEstablished;
        }

        Flow* const flow = &it->second;
        const error_code_t emit_result = emit_tcp_response(
                flow->connection_info,
                flow->server_next_sequence,
                flow->client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().flags(),
                payload,
                payload_size);
        if (emit_result != ErrorCode::Ok) {
            return emit_result;
        }
        flow->server_next_sequence += static_cast<uint32_t>(payload_size);
        return ErrorCode::Ok;
    }

    error_code_t close_flow(const ConnectionInfo& connection_info) {
        if (connection_info.ip_ver != 4) {
            emit_error(ErrorCode::Ipv4OnlyOperation);
            return ErrorCode::Ipv4OnlyOperation;
        }

        FlowMap::iterator it = ipv4_flows_.find(connection_info);
        if (it == ipv4_flows_.end()) {
            emit_error(ErrorCode::FlowNotFound);
            return ErrorCode::FlowNotFound;
        }

        if (it->second.state != FlowState::Established) {
            emit_error(ErrorCode::CloseBeforeEstablished);
            return ErrorCode::CloseBeforeEstablished;
        }

        Flow* flow = &it->second;
        const error_code_t emit_result = emit_tcp_response(
                flow->connection_info,
                flow->server_next_sequence,
                flow->client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().set_fin().flags(),
                NULL,
                0);
        if (emit_result != ErrorCode::Ok) {
            return emit_result;
        }
        flow->server_next_sequence += 1;
        flow->state = FlowState::LastAck;
        return ErrorCode::Ok;
    }


private:
    enum class FlowState {
        SynReceived,
        Established,
        LastAck
    };

    struct Flow {
        ConnectionInfo connection_info;
        FlowState state;
        uint32_t client_next_sequence;
        uint32_t server_initial_sequence;
        uint32_t server_next_sequence;

        Flow(
            const ConnectionInfo& flow_connection_info,
            FlowState flow_state,
            uint32_t client_next_sequence_value,
            uint32_t server_initial_sequence_value,
            uint32_t server_next_sequence_value)
            : connection_info(flow_connection_info),
              state(flow_state),
              client_next_sequence(client_next_sequence_value),
              server_initial_sequence(server_initial_sequence_value),
              server_next_sequence(server_next_sequence_value) {}
    };

    using FlowMap = std::unordered_map<ConnectionInfo, Flow, ConnectionInfoHash, ConnectionInfoEqual>;

    error_code_t handle_incoming_ip4_tcp_packet(const Ip4PacketView & ipv4_packet) {
        TcpSegment tcp_segment;
        const error_code_t tcp_parse_result = parse_tcp_segment(ipv4_packet.payload, ipv4_packet.payload_size, tcp_segment);
        if (tcp_parse_result != ErrorCode::Ok) {
            return tcp_parse_result;
        }

        const ConnectionInfo key(
            ipv4_packet.source_address,
            ipv4_packet.destination_address,
            tcp_segment.source_port,
            tcp_segment.destination_port);
        if (tcp_segment.is_syn() && !tcp_segment.is_ack()) {
            return handle_syn(key, tcp_segment.sequence_number);
        }

        FlowMap::iterator it = ipv4_flows_.find(key);
        if (it == ipv4_flows_.end()) {
            if (tcp_segment.is_rst()) {
                return ErrorCode::Ok;
            }
            emit_reset_for_unhandled_packet(
                key,
                tcp_segment.sequence_number,
                tcp_segment.acknowledgment_number,
                tcp_segment.flags,
                tcp_segment.payload.size());
            return ErrorCode::FlowNotFound;
        }

        Flow* flow = &it->second;
        if (tcp_segment.is_rst()) {
            const ConnectionInfo reset_flow = flow->connection_info;
            ipv4_flows_.erase(reset_flow);
            emit_reset(reset_flow);
            return ErrorCode::Ok;
        }

        if (flow->state == FlowState::SynReceived) {
            if (!tcp_segment.is_ack() || tcp_segment.acknowledgment_number != flow->server_next_sequence) {
                return fail_flow(
                    flow->connection_info,
                    ErrorCode::HandshakeFinalAckExpected,
                    tcp_segment);
            }

            if (tcp_segment.sequence_number != flow->client_next_sequence) {
                return fail_flow(
                    flow->connection_info,
                    ErrorCode::HandshakeClientSequenceUnexpected,
                    tcp_segment);
            }

            flow->state = FlowState::Established;
            if (callbacks_.on_tcp_handshake_completed != NULL) {
                callbacks_.on_tcp_handshake_completed(callbacks_.user_data, flow->connection_info);
            }
            return ErrorCode::Ok;
        }

        if (flow->state == FlowState::Established) {
            return handle_established_packet(
                flow,
                tcp_segment);
        }

        return handle_last_ack_packet(flow, tcp_segment);
    }

    void emit_error(error_code_t error_code) const {
        if (callbacks_.on_error != NULL) {
            callbacks_.on_error(callbacks_.user_data, error_code);
        }
    }

    void emit_downstream_ip_packet(const void* ip_packet, size_t ip_packet_size) const {
        if (callbacks_.on_downstream_ip_packet_generated != NULL) {
            callbacks_.on_downstream_ip_packet_generated(callbacks_.user_data, ip_packet, ip_packet_size);
        }
    }

    void emit_reset(const ConnectionInfo& connection_info) const {
        if (callbacks_.on_tcp_connection_reset != NULL) {
            callbacks_.on_tcp_connection_reset(callbacks_.user_data, connection_info);
        }
    }

    error_code_t handle_syn(const ConnectionInfo& connection_info, uint32_t client_sequence) {
        const uint32_t client_next_sequence = client_sequence + 1;
        const uint32_t server_initial_sequence = 7000 + static_cast<uint32_t>(ipv4_flows_.size()) * 1024U;
        const uint32_t server_next_sequence = server_initial_sequence + 1;
        const Flow flow(
            connection_info,
            FlowState::SynReceived,
            client_next_sequence,
            server_initial_sequence,
            server_next_sequence);

        std::pair<FlowMap::iterator, bool> inserted =
            ipv4_flows_.insert(std::make_pair(connection_info, flow));
        if (!inserted.second) {
            emit_error(ErrorCode::FlowAlreadyExists);
            return ErrorCode::FlowAlreadyExists;
        }

        const error_code_t emit_result = emit_tcp_response(
                connection_info,
                server_initial_sequence,
                client_next_sequence,
                TcpSegment::FlagsBuilder().set_syn().set_ack().flags(),
                NULL,
                0);
        if (emit_result != ErrorCode::Ok) {
            ipv4_flows_.erase(connection_info);
            return emit_result;
        }
        return ErrorCode::Ok;
    }

    error_code_t handle_established_packet(
        Flow* flow,
        const TcpSegment& segment) {
        if (segment.is_rst()) {
            const ConnectionInfo reset_flow = flow->connection_info;
            ipv4_flows_.erase(reset_flow);
            emit_reset(reset_flow);
            return ErrorCode::Ok;
        }

        if (!segment.is_ack()) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::EstablishedAckRequired,
                segment);
        }

        if (segment.acknowledgment_number != flow->server_next_sequence) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::EstablishedAckNumberUnexpected,
                segment);
        }

        if (segment.sequence_number != flow->client_next_sequence) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::EstablishedSequenceUnexpected,
                segment);
        }

        if (!segment.payload.empty()) {
            flow->client_next_sequence += static_cast<uint32_t>(segment.payload.size());
            if (callbacks_.on_tcp_payload_received != NULL) {
                callbacks_.on_tcp_payload_received(
                    callbacks_.user_data,
                    flow->connection_info,
                    &segment.payload[0],
                    segment.payload.size());
            }
            return emit_tcp_response(
                flow->connection_info,
                flow->server_next_sequence,
                flow->client_next_sequence,
                TcpSegment::FlagsBuilder().set_ack().flags(),
                NULL,
                0);
        }

        if (segment.is_fin()) {
            flow->client_next_sequence += 1;
            flow->state = FlowState::LastAck;
            const error_code_t emit_result = emit_tcp_response(
                    flow->connection_info,
                    flow->server_next_sequence,
                    flow->client_next_sequence,
                    TcpSegment::FlagsBuilder().set_ack().set_fin().flags(),
                    NULL,
                    0);
            if (emit_result != ErrorCode::Ok) {
                return emit_result;
            }
            flow->server_next_sequence += 1;
            return ErrorCode::Ok;
        }

        return ErrorCode::Ok;
    }

    error_code_t handle_last_ack_packet(
        Flow* flow,
        const TcpSegment& segment) {
        if (!segment.is_ack()) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::CloseFinalAckExpected,
                segment);
        }

        if (segment.acknowledgment_number != flow->server_next_sequence) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::CloseAckUnexpected,
                segment);
        }

        const ConnectionInfo completed_flow = flow->connection_info;
        ipv4_flows_.erase(completed_flow);
        if (callbacks_.on_tcp_connection_closed != NULL) {
            callbacks_.on_tcp_connection_closed(callbacks_.user_data, completed_flow);
        }
        return ErrorCode::Ok;
    }

    error_code_t emit_reset_for_unhandled_packet(
        const ConnectionInfo& connection_info,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        uint8_t flags,
        size_t payload_size) {
        if (flags & TcpSegment::BITS_MASK_ACK) {
            return emit_tcp_response(
                connection_info,
                acknowledgment_number,
                0,
                TcpSegment::FlagsBuilder().set_rst().flags(),
                NULL,
                0);
        }

        uint32_t ack_number = sequence_number + static_cast<uint32_t>(payload_size);
        if (flags & TcpSegment::BITS_MASK_SYN) {
            ++ack_number;
        }
        if (flags & TcpSegment::BITS_MASK_FIN) {
            ++ack_number;
        }
        return emit_tcp_response(
            connection_info,
            0,
            ack_number,
            TcpSegment::FlagsBuilder().set_ack().set_rst().flags(),
            NULL,
            0);
    }

    error_code_t fail_flow(
        const ConnectionInfo& connection_info,
        error_code_t error_code,
        const TcpSegment& segment) {
        ipv4_flows_.erase(connection_info);
        emit_reset_for_unhandled_packet(
            connection_info,
            segment.sequence_number,
            segment.acknowledgment_number,
            segment.flags,
            segment.payload.size());
        emit_reset(connection_info);
        return error_code;
    }

    error_code_t emit_tcp_response(
        const ConnectionInfo& connection_info,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        uint8_t flags,
        const void* payload,
        size_t payload_size) {
        const std::vector<uint8_t> tcp_bytes = serialize_tcp_segment_with_checksum(
            connection_info,
            sequence_number,
            acknowledgment_number,
            flags,
            payload,
            payload_size);

        std::vector<uint8_t> ipv4_bytes;
        Ip4Head head = {};
        head.version_ihl = 0x45;
        head.ttl = 64;
        head.protocol = 6;
        std::memcpy(&head.source_address, &connection_info.server_ip.ipv4, sizeof(head.source_address));
        std::memcpy(&head.destination_address, &connection_info.client_ip.ipv4, sizeof(head.destination_address));
        const error_code_t serialize_result = serialize_ipv4_packet(head, &tcp_bytes[0], tcp_bytes.size(), &ipv4_bytes);
        if (serialize_result != ErrorCode::Ok) {
            emit_error(ErrorCode::PacketEmitFailed);
            return ErrorCode::PacketEmitFailed;
        }
        emit_downstream_ip_packet(&ipv4_bytes[0], ipv4_bytes.size());
        return ErrorCode::Ok;
    }

private:
    MirageTcpCallbacks callbacks_;
    FlowMap ipv4_flows_;
};

MirageTcp::MirageTcp(const MirageTcpCallbacks& callbacks)
    : impl_(new Impl(callbacks))
{}

MirageTcp::MirageTcp(MirageTcp && other)
    : impl_(std::move(other.impl_))
{}

MirageTcp & MirageTcp::operator=(MirageTcp && rv) {
    if (this != &rv) {
        this->impl_.reset();
        std::swap(this->impl_, rv.impl_);
    }
    return *this;
}

MirageTcp::~MirageTcp() = default;

error_code_t MirageTcp::handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size) {
    return impl_->handle_incoming_ip_packet(ip_packet, ip_packet_size);
}

error_code_t MirageTcp::send_downstream_tcp_payload(
    const ConnectionInfo& connection_info,
    const void* payload,
    size_t payload_size)
{
    return impl_->send_downstream_tcp_payload(connection_info, payload, payload_size);
}

error_code_t MirageTcp::close_flow(const ConnectionInfo& connection_info) {
    return impl_->close_flow(connection_info);
}

}  // namespace mirage_tcp
