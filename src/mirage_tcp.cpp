#include "mirage_tcp/mirage_tcp.h"

#include <cstring>
#include <vector>

#include "mirage_tcp/ipv4_packet.h"
#include "mirage_tcp/tcp_segment.h"
#include "ipv4_packet_internal.h"

namespace mirage_tcp {

namespace {

uint16_t read_u16_be(const uint8_t* bytes) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) |
        static_cast<uint16_t>(bytes[1]));
}

void write_u16_be(uint16_t value, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[1] = static_cast<uint8_t>(value & 0xff);
}

uint16_t internet_checksum(const uint8_t* data, size_t size) {
    uint32_t sum = 0;
    size_t index = 0;
    while (index + 1 < size) {
        sum += read_u16_be(data + index);
        index += 2;
    }
    if (index < size) {
        sum += static_cast<uint16_t>(static_cast<uint16_t>(data[index]) << 8);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

std::vector<uint8_t> serialize_tcp_segment_with_checksum(
    const ConnectionInfo& connection_info,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    bool syn_flag,
    bool ack_flag,
    bool fin_flag,
    bool rst_flag,
    const void* payload,
    size_t payload_size) {
    TcpSegment segment;
    segment.source_port = connection_info.server_port;
    segment.destination_port = connection_info.client_port;
    segment.sequence_number = sequence_number;
    segment.acknowledgment_number = acknowledgment_number;
    segment.window_size = 65535;
    segment.syn = syn_flag;
    segment.ack = ack_flag;
    segment.fin = fin_flag;
    segment.rst = rst_flag;
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
    const uint16_t checksum = internet_checksum(&pseudo_header[0], pseudo_header.size());
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

ConnectionInfo::ConnectionInfo()
    : client_port(0),
      server_port(0),
      ip_ver(0) {
    std::memset(&client_ip, 0, sizeof(client_ip));
    std::memset(&server_ip, 0, sizeof(server_ip));
}

bool operator<(const ConnectionInfo& left, const ConnectionInfo& right) {
    if (left.ip_ver != right.ip_ver) {
        return left.ip_ver < right.ip_ver;
    }

    const size_t address_size = left.ip_ver == 6 ? sizeof(left.client_ip.ipv6) : sizeof(left.client_ip.ipv4);
    const int client_compare = std::memcmp(&left.client_ip, &right.client_ip, address_size);
    if (client_compare != 0) {
        return client_compare < 0;
    }
    const int server_compare = std::memcmp(&left.server_ip, &right.server_ip, address_size);
    if (server_compare != 0) {
        return server_compare < 0;
    }
    if (left.client_port != right.client_port) {
        return left.client_port < right.client_port;
    }
    return left.server_port < right.server_port;
}

MirageTcpCallbacks::MirageTcpCallbacks()
    : user_data(NULL),
      on_downstream_ip_packet_generated(NULL),
      on_tcp_handshake_completed(NULL),
      on_tcp_payload_received(NULL),
      on_tcp_connection_closed(NULL),
      on_tcp_connection_reset(NULL),
      on_error(NULL) {}

MirageTcp::MirageTcp(const MirageTcpCallbacks& callbacks)
    : callbacks_(callbacks) {}

error_code_t MirageTcp::handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size) {
    if (ip_packet == nullptr) {
        return ErrorCode::InvalidArgument;
    }

    Ip4PacketView ipv4_packet;
    const error_code_t ipv4_parse_result = parse_ipv4_tcp_packet(ip_packet, ip_packet_size, ipv4_packet);
    if (ipv4_parse_result != ErrorCode::Ok) {
        const error_code_t ipv6_parse_result = parse_ipv6_tcp_packet(ip_packet, ip_packet_size);
        if (ipv6_parse_result == ErrorCode::Unsupported) {
            return ipv6_parse_result;
        }
        return ipv4_parse_result;
    }

    TcpSegment tcp_segment;
    const error_code_t tcp_parse_result = parse_tcp_segment(ipv4_packet.payload, ipv4_packet.payload_size, &tcp_segment);
    if (tcp_parse_result != ErrorCode::Ok) {
        return tcp_parse_result;
    }

    ConnectionInfo key;
    std::memcpy(&key.client_ip.ipv4, &ipv4_packet.head->source_address, sizeof(ipv4_packet.head->source_address));
    std::memcpy(&key.server_ip.ipv4, &ipv4_packet.head->destination_address, sizeof(ipv4_packet.head->destination_address));
    key.client_port = tcp_segment.source_port;
    key.server_port = tcp_segment.destination_port;
    key.ip_ver = 4;

    std::map<ConnectionInfo, Flow>::iterator it = ipv4_flows_.find(key);
    if (tcp_segment.syn && !tcp_segment.ack) {
        return handle_syn(key, tcp_segment.sequence_number);
    }

    if (it == ipv4_flows_.end()) {
        if (tcp_segment.rst) {
            return ErrorCode::Ok;
        }
        emit_reset_for_unhandled_packet(
            key,
            tcp_segment.sequence_number,
            tcp_segment.acknowledgment_number,
            tcp_segment.ack,
            tcp_segment.syn,
            tcp_segment.fin,
            tcp_segment.payload.size());
        return ErrorCode::FlowNotFound;
    }

    Flow* flow = &it->second;
    if (tcp_segment.rst) {
        const ConnectionInfo reset_flow = flow->connection_info;
        ipv4_flows_.erase(reset_flow);
        emit_reset(reset_flow);
        return ErrorCode::Ok;
    }

    if (flow->state == FlowState::kSynReceived) {
        if (!tcp_segment.ack || tcp_segment.acknowledgment_number != flow->server_next_sequence) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::HandshakeFinalAckExpected,
                tcp_segment.sequence_number,
                tcp_segment.acknowledgment_number,
                tcp_segment.ack,
                tcp_segment.syn,
                tcp_segment.fin,
                tcp_segment.payload.size());
        }

        if (tcp_segment.sequence_number != flow->client_next_sequence) {
            return fail_flow(
                flow->connection_info,
                ErrorCode::HandshakeClientSequenceUnexpected,
                tcp_segment.sequence_number,
                tcp_segment.acknowledgment_number,
                tcp_segment.ack,
                tcp_segment.syn,
                tcp_segment.fin,
                tcp_segment.payload.size());
        }

        flow->state = FlowState::kEstablished;
        if (callbacks_.on_tcp_handshake_completed != NULL) {
            callbacks_.on_tcp_handshake_completed(callbacks_.user_data, flow->connection_info);
        }
        return ErrorCode::Ok;
    }

    if (flow->state == FlowState::kEstablished) {
        return handle_established_packet(
            flow,
            tcp_segment.sequence_number,
            tcp_segment.acknowledgment_number,
            tcp_segment.ack,
            tcp_segment.fin,
            tcp_segment.rst,
            tcp_segment.payload.empty() ? NULL : &tcp_segment.payload[0],
            tcp_segment.payload.size());
    }

    return handle_last_ack_packet(flow, tcp_segment.acknowledgment_number, tcp_segment.ack);
}

error_code_t MirageTcp::send_downstream_tcp_payload(
    const ConnectionInfo& connection_info,
    const void* payload,
    size_t payload_size) {
    if (payload == NULL || payload_size == 0) {
        emit_error(ErrorCode::PayloadEmpty);
        return ErrorCode::PayloadEmpty;
    }

    if (connection_info.ip_ver != 4) {
        emit_error(ErrorCode::Ipv4OnlyOperation);
        return ErrorCode::Ipv4OnlyOperation;
    }

    std::map<ConnectionInfo, Flow>::iterator it = ipv4_flows_.find(connection_info);
    if (it == ipv4_flows_.end()) {
        emit_error(ErrorCode::FlowNotFound);
        return ErrorCode::FlowNotFound;
    }

    if (it->second.state != FlowState::kEstablished) {
        emit_error(ErrorCode::SendBeforeEstablished);
        return ErrorCode::SendBeforeEstablished;
    }

    Flow* flow = &it->second;
    const error_code_t emit_result = emit_tcp_response(
            flow->connection_info,
            flow->server_next_sequence,
            flow->client_next_sequence,
            false,
            true,
            false,
            false,
            payload,
            payload_size);
    if (emit_result != ErrorCode::Ok) {
        return emit_result;
    }
    flow->server_next_sequence += static_cast<uint32_t>(payload_size);
    return ErrorCode::Ok;
}

error_code_t MirageTcp::close_flow(const ConnectionInfo& connection_info) {
    if (connection_info.ip_ver != 4) {
        emit_error(ErrorCode::Ipv4OnlyOperation);
        return ErrorCode::Ipv4OnlyOperation;
    }

    std::map<ConnectionInfo, Flow>::iterator it = ipv4_flows_.find(connection_info);
    if (it == ipv4_flows_.end()) {
        emit_error(ErrorCode::FlowNotFound);
        return ErrorCode::FlowNotFound;
    }

    if (it->second.state != FlowState::kEstablished) {
        emit_error(ErrorCode::CloseBeforeEstablished);
        return ErrorCode::CloseBeforeEstablished;
    }

    Flow* flow = &it->second;
    const error_code_t emit_result = emit_tcp_response(
            flow->connection_info,
            flow->server_next_sequence,
            flow->client_next_sequence,
            false,
            true,
            true,
            false,
            NULL,
            0);
    if (emit_result != ErrorCode::Ok) {
        return emit_result;
    }
    flow->server_next_sequence += 1;
    flow->state = FlowState::kLastAck;
    return ErrorCode::Ok;
}

void MirageTcp::emit_error(error_code_t error_code) const {
    if (callbacks_.on_error != NULL) {
        callbacks_.on_error(callbacks_.user_data, error_code);
    }
}

void MirageTcp::emit_downstream_ip_packet(const void* ip_packet, size_t ip_packet_size) const {
    if (callbacks_.on_downstream_ip_packet_generated != NULL) {
        callbacks_.on_downstream_ip_packet_generated(callbacks_.user_data, ip_packet, ip_packet_size);
    }
}

void MirageTcp::emit_reset(const ConnectionInfo& connection_info) const {
    if (callbacks_.on_tcp_connection_reset != NULL) {
        callbacks_.on_tcp_connection_reset(callbacks_.user_data, connection_info);
    }
}

error_code_t MirageTcp::handle_syn(const ConnectionInfo& connection_info, uint32_t client_sequence) {
    Flow flow;
    flow.connection_info = connection_info;
    flow.state = FlowState::kSynReceived;
    flow.client_next_sequence = client_sequence + 1;
    flow.server_initial_sequence = 7000 + static_cast<uint32_t>(ipv4_flows_.size()) * 1024U;
    flow.server_next_sequence = flow.server_initial_sequence + 1;

    std::pair<std::map<ConnectionInfo, Flow>::iterator, bool> inserted =
        ipv4_flows_.insert(std::make_pair(connection_info, flow));
    if (!inserted.second) {
        emit_error(ErrorCode::FlowAlreadyExists);
        return ErrorCode::FlowAlreadyExists;
    }

    const error_code_t emit_result = emit_tcp_response(
            connection_info,
            flow.server_initial_sequence,
            flow.client_next_sequence,
            true,
            true,
            false,
            false,
            NULL,
            0);
    if (emit_result != ErrorCode::Ok) {
        ipv4_flows_.erase(connection_info);
        return emit_result;
    }
    return ErrorCode::Ok;
}

error_code_t MirageTcp::handle_established_packet(
    Flow* flow,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    bool ack_flag,
    bool fin_flag,
    bool rst_flag,
    const void* payload,
    size_t payload_size) {
    if (rst_flag) {
        const ConnectionInfo reset_flow = flow->connection_info;
        ipv4_flows_.erase(reset_flow);
        emit_reset(reset_flow);
        return ErrorCode::Ok;
    }

    if (!ack_flag) {
        return fail_flow(
            flow->connection_info,
            ErrorCode::EstablishedAckRequired,
            sequence_number,
            acknowledgment_number,
            ack_flag,
            false,
            fin_flag,
            payload_size);
    }

    if (acknowledgment_number != flow->server_next_sequence) {
        return fail_flow(
            flow->connection_info,
            ErrorCode::EstablishedAckNumberUnexpected,
            sequence_number,
            acknowledgment_number,
            ack_flag,
            false,
            fin_flag,
            payload_size);
    }

    if (sequence_number != flow->client_next_sequence) {
        return fail_flow(
            flow->connection_info,
            ErrorCode::EstablishedSequenceUnexpected,
            sequence_number,
            acknowledgment_number,
            ack_flag,
            false,
            fin_flag,
            payload_size);
    }

    if (payload_size > 0) {
        flow->client_next_sequence += static_cast<uint32_t>(payload_size);
        if (callbacks_.on_tcp_payload_received != NULL) {
            callbacks_.on_tcp_payload_received(
                callbacks_.user_data,
                flow->connection_info,
                payload,
                payload_size);
        }
        return emit_tcp_response(
            flow->connection_info,
            flow->server_next_sequence,
            flow->client_next_sequence,
            false,
            true,
            false,
            false,
            NULL,
            0);
    }

    if (fin_flag) {
        flow->client_next_sequence += 1;
        flow->state = FlowState::kLastAck;
        const error_code_t emit_result = emit_tcp_response(
                flow->connection_info,
                flow->server_next_sequence,
                flow->client_next_sequence,
                false,
                true,
                true,
                false,
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

error_code_t MirageTcp::handle_last_ack_packet(
    Flow* flow,
    uint32_t acknowledgment_number,
    bool ack_flag) {
    if (!ack_flag) {
        return fail_flow(
            flow->connection_info,
            ErrorCode::CloseFinalAckExpected,
            0,
            acknowledgment_number,
            false,
            false,
            false,
            0);
    }

    if (acknowledgment_number != flow->server_next_sequence) {
        return fail_flow(
            flow->connection_info,
            ErrorCode::CloseAckUnexpected,
            0,
            acknowledgment_number,
            true,
            false,
            false,
            0);
    }

    const ConnectionInfo completed_flow = flow->connection_info;
    ipv4_flows_.erase(completed_flow);
    if (callbacks_.on_tcp_connection_closed != NULL) {
        callbacks_.on_tcp_connection_closed(callbacks_.user_data, completed_flow);
    }
    return ErrorCode::Ok;
}

error_code_t MirageTcp::emit_reset_for_unhandled_packet(
    const ConnectionInfo& connection_info,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    bool ack_flag,
    bool syn_flag,
    bool fin_flag,
    size_t payload_size) {
    if (ack_flag) {
        return emit_tcp_response(
            connection_info,
            acknowledgment_number,
            0,
            false,
            false,
            false,
            true,
            NULL,
            0);
    }

    uint32_t ack_number = sequence_number + static_cast<uint32_t>(payload_size);
    if (syn_flag) {
        ++ack_number;
    }
    if (fin_flag) {
        ++ack_number;
    }
    return emit_tcp_response(
        connection_info,
        0,
        ack_number,
        false,
        true,
        false,
        true,
        NULL,
        0);
}

error_code_t MirageTcp::fail_flow(
    const ConnectionInfo& connection_info,
    error_code_t error_code,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    bool ack_flag,
    bool syn_flag,
    bool fin_flag,
    size_t payload_size) {
    ipv4_flows_.erase(connection_info);
    emit_reset_for_unhandled_packet(
        connection_info,
        sequence_number,
        acknowledgment_number,
        ack_flag,
        syn_flag,
        fin_flag,
        payload_size);
    emit_reset(connection_info);
    return error_code;
}

error_code_t MirageTcp::emit_tcp_response(
    const ConnectionInfo& connection_info,
    uint32_t sequence_number,
    uint32_t acknowledgment_number,
    bool syn_flag,
    bool ack_flag,
    bool fin_flag,
    bool rst_flag,
    const void* payload,
    size_t payload_size) {
    const std::vector<uint8_t> tcp_bytes = serialize_tcp_segment_with_checksum(
        connection_info,
        sequence_number,
        acknowledgment_number,
        syn_flag,
        ack_flag,
        fin_flag,
        rst_flag,
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

}  // namespace mirage_tcp
