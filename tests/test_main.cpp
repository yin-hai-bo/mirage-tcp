#include <cstddef>
#include <cstring>
#include <cstdint>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "mirage_tcp/ipv4_packet.h"
#include "mirage_tcp/mirage_tcp.h"
#include "mirage_tcp/tcp_segment.h"

namespace {

struct TestCase {
    const char* name;
    std::function<void()> run;
};

struct CallbackContext {
    std::vector<std::vector<std::uint8_t> > downstream_packets;
    std::vector<mirage_tcp::ConnectionInfo> handshakes;
    std::vector<std::vector<std::uint8_t> > payloads;
    std::vector<mirage_tcp::ConnectionInfo> closed_flows;
    std::vector<mirage_tcp::ConnectionInfo> reset_flows;
    std::vector<mirage_tcp::error_code_t> errors;
};

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void on_downstream_ip_packet_generated(void* user_data, const void* ip_packet, std::size_t ip_packet_size) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(ip_packet);
    context->downstream_packets.push_back(
        std::vector<std::uint8_t>(bytes, bytes + static_cast<std::ptrdiff_t>(ip_packet_size)));
}

mirage_tcp::in_addr make_ipv4_address(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    mirage_tcp::in_addr address;
    const std::uint8_t bytes[4] = {a, b, c, d};
    std::memcpy(&address, bytes, sizeof(address));
    return address;
}

bool same_ipv4_address(const mirage_tcp::in_addr& left, const mirage_tcp::in_addr& right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

void on_tcp_handshake_completed(void* user_data, const mirage_tcp::ConnectionInfo& connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->handshakes.push_back(connection_info);
}

void on_tcp_payload_received(
    void* user_data,
    const mirage_tcp::ConnectionInfo&,
    const void* payload,
    std::size_t payload_size) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(payload);
    context->payloads.push_back(
        std::vector<std::uint8_t>(bytes, bytes + static_cast<std::ptrdiff_t>(payload_size)));
}

void on_tcp_connection_closed(void* user_data, const mirage_tcp::ConnectionInfo& connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->closed_flows.push_back(connection_info);
}

void on_tcp_connection_reset(void* user_data, const mirage_tcp::ConnectionInfo& connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->reset_flows.push_back(connection_info);
}

void on_error(void* user_data, mirage_tcp::error_code_t error_code) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->errors.push_back(error_code);
}

mirage_tcp::MirageTcp make_mirage_tcp(CallbackContext* context) {
    mirage_tcp::MirageTcpCallbacks callbacks;
    callbacks.user_data = context;
    callbacks.on_downstream_ip_packet_generated = on_downstream_ip_packet_generated;
    callbacks.on_tcp_handshake_completed = on_tcp_handshake_completed;
    callbacks.on_tcp_payload_received = on_tcp_payload_received;
    callbacks.on_tcp_connection_closed = on_tcp_connection_closed;
    callbacks.on_tcp_connection_reset = on_tcp_connection_reset;
    callbacks.on_error = on_error;
    return mirage_tcp::MirageTcp(callbacks);
}

mirage_tcp::ConnectionInfo make_flow() {
    mirage_tcp::ConnectionInfo flow;
    flow.client_ip.ipv4 = make_ipv4_address(10, 0, 0, 1);
    flow.server_ip.ipv4 = make_ipv4_address(93, 184, 216, 34);
    flow.client_port = 49152;
    flow.server_port = 443;
    flow.ip_ver = 4;
    return flow;
}

std::vector<std::uint8_t> build_client_packet(
    const mirage_tcp::ConnectionInfo& flow,
    std::uint32_t sequence_number,
    std::uint32_t acknowledgment_number,
    bool syn,
    bool ack,
    bool fin,
    const std::vector<std::uint8_t>& payload) {
    mirage_tcp::TcpSegment segment;
    segment.source_port = flow.client_port;
    segment.destination_port = flow.server_port;
    segment.sequence_number = sequence_number;
    segment.acknowledgment_number = acknowledgment_number;
    segment.window_size = 65535;
    segment.syn = syn;
    segment.ack = ack;
    segment.fin = fin;
    segment.rst = false;
    segment.payload = payload;

    mirage_tcp::Ipv4Packet packet;
    std::memcpy(&packet.source_address, &flow.client_ip.ipv4, sizeof(packet.source_address));
    std::memcpy(&packet.destination_address, &flow.server_ip.ipv4, sizeof(packet.destination_address));
    packet.protocol = 6;
    packet.ttl = 64;
    packet.payload = mirage_tcp::serialize_tcp_segment(segment);
    std::vector<std::uint8_t> bytes;
    require(
        mirage_tcp::serialize_ipv4_packet(packet, &bytes) == mirage_tcp::ErrorCode::Ok,
        "client packet serialization should succeed");
    return bytes;
}

mirage_tcp::TcpSegment parse_tcp_from_ip(const std::vector<std::uint8_t>& packet_bytes) {
    mirage_tcp::Ipv4Packet ip_packet;
    require(
        mirage_tcp::parse_ipv4_packet(&packet_bytes[0], packet_bytes.size(), &ip_packet) == mirage_tcp::ErrorCode::Ok,
        "ipv4 parse should succeed");

    mirage_tcp::TcpSegment segment;
    require(
        mirage_tcp::parse_tcp_segment(ip_packet.payload, &segment) == mirage_tcp::ErrorCode::Ok,
        "tcp parse should succeed");
    return segment;
}

void test_ipv4_roundtrip() {
    mirage_tcp::Ipv4Packet packet;
    const mirage_tcp::in_addr source_address = make_ipv4_address(10, 0, 0, 1);
    const mirage_tcp::in_addr destination_address = make_ipv4_address(10, 0, 0, 2);
    std::memcpy(&packet.source_address, &source_address, sizeof(packet.source_address));
    std::memcpy(&packet.destination_address, &destination_address, sizeof(packet.destination_address));
    packet.protocol = 6;
    packet.ttl = 42;
    packet.payload.assign(5, 0x11);

    std::vector<std::uint8_t> bytes;
    require(
        mirage_tcp::serialize_ipv4_packet(packet, &bytes) == mirage_tcp::ErrorCode::Ok,
        "ipv4 serialize should succeed");

    mirage_tcp::Ipv4Packet parsed;
    require(
        mirage_tcp::parse_ipv4_packet(&bytes[0], bytes.size(), &parsed) == mirage_tcp::ErrorCode::Ok,
        "ipv4 parse should succeed");
    require(std::memcmp(&parsed.source_address, &packet.source_address, sizeof(packet.source_address)) == 0, "ipv4 source mismatch");
    require(
        std::memcmp(&parsed.destination_address, &packet.destination_address, sizeof(packet.destination_address)) == 0,
        "ipv4 destination mismatch");
    require(parsed.protocol == packet.protocol, "ipv4 protocol mismatch");
    require(parsed.payload == packet.payload, "ipv4 payload mismatch");
}

void test_syn_generates_downstream_syn_ack() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    require(context.downstream_packets.size() == 1, "SYN should generate one downstream packet");
    require(context.handshakes.empty(), "handshake should not complete after SYN only");

    mirage_tcp::TcpSegment response = parse_tcp_from_ip(context.downstream_packets[0]);
    require(response.syn, "response should contain SYN");
    require(response.ack, "response should contain ACK");
    require(!response.fin, "response should not contain FIN");
    require(response.acknowledgment_number == 1001, "SYN+ACK must acknowledge client SYN");
}

void test_final_ack_completes_handshake() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");

    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);
    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");
    require(context.handshakes.size() == 1, "handshake callback should fire once");
    require(context.handshakes[0].client_port == flow.client_port, "handshake flow client port mismatch");
    require(context.handshakes[0].ip_ver == 4, "handshake flow ip version mismatch");
    require(same_ipv4_address(context.handshakes[0].client_ip.ipv4, flow.client_ip.ipv4), "handshake flow client ip mismatch");
}

void test_payload_is_reported_and_acked() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> payload;
    payload.push_back('o');
    payload.push_back('k');
    std::vector<std::uint8_t> payload_packet = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        payload);
    require(mirage_tcp.handle_incoming_ip_packet(&payload_packet[0], payload_packet.size()) == mirage_tcp::ErrorCode::Ok, "payload should be accepted");

    require(context.payloads.size() == 1, "payload callback should fire once");
    require(context.payloads[0] == payload, "payload callback content mismatch");
    require(context.downstream_packets.size() == 2, "payload should generate one ACK packet");
    mirage_tcp::TcpSegment ack_only = parse_tcp_from_ip(context.downstream_packets[1]);
    require(ack_only.ack, "payload response should ACK");
    require(ack_only.acknowledgment_number == 1003, "payload ACK number mismatch");
}

void test_fin_generates_fin_ack_and_close_event() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> fin_packet = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        true,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&fin_packet[0], fin_packet.size()) == mirage_tcp::ErrorCode::Ok, "FIN should be accepted");
    require(context.downstream_packets.size() == 2, "FIN should generate one FIN+ACK");
    mirage_tcp::TcpSegment fin_ack = parse_tcp_from_ip(context.downstream_packets[1]);
    require(fin_ack.fin, "response to FIN should include FIN");
    require(fin_ack.ack, "response to FIN should include ACK");

    std::vector<std::uint8_t> final_close_ack = build_client_packet(
        flow,
        1002,
        fin_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp.handle_incoming_ip_packet(&final_close_ack[0], final_close_ack.size()) == mirage_tcp::ErrorCode::Ok,
        "final close ACK should be accepted");
    require(context.closed_flows.size() == 1, "close callback should fire once");
}

void test_invalid_flow_reports_error() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> ack_packet = build_client_packet(
        flow,
        1001,
        2000,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&ack_packet[0], ack_packet.size()) == mirage_tcp::ErrorCode::FlowNotFound, "unknown flow should be handled with reset");
    require(!context.errors.empty(), "unknown flow should emit error");
    require(context.errors[0] == mirage_tcp::ErrorCode::FlowNotFound, "unknown flow should emit flow-not-found error code");
    require(context.downstream_packets.size() == 1, "unknown flow should generate one reset packet");
    mirage_tcp::TcpSegment reset = parse_tcp_from_ip(context.downstream_packets[0]);
    require(reset.rst, "unknown flow response should be RST");
}

void test_send_downstream_payload_generates_data_segment() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> payload;
    payload.push_back('p');
    payload.push_back('o');
    payload.push_back('n');
    payload.push_back('g');
    require(
        mirage_tcp.send_downstream_tcp_payload(flow, &payload[0], payload.size()) == mirage_tcp::ErrorCode::Ok,
        "send_downstream_tcp_payload should succeed");
    require(context.downstream_packets.size() == 2, "downstream payload should generate one packet");
    mirage_tcp::TcpSegment response = parse_tcp_from_ip(context.downstream_packets[1]);
    require(response.ack, "downstream payload should carry ACK");
    require(response.payload == payload, "downstream payload content mismatch");

    std::vector<std::uint8_t> payload_ack = build_client_packet(
        flow,
        1001,
        response.sequence_number + static_cast<std::uint32_t>(payload.size()),
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp.handle_incoming_ip_packet(&payload_ack[0], payload_ack.size()) == mirage_tcp::ErrorCode::Ok,
        "client ACK for downstream payload should be accepted");
}

void test_close_flow_generates_fin_ack_and_close_event() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");

    require(mirage_tcp.close_flow(flow) == mirage_tcp::ErrorCode::Ok, "close_flow should succeed");
    require(context.downstream_packets.size() == 2, "close_flow should generate one FIN+ACK");
    mirage_tcp::TcpSegment fin_ack = parse_tcp_from_ip(context.downstream_packets[1]);
    require(fin_ack.fin, "close_flow response should include FIN");
    require(fin_ack.ack, "close_flow response should include ACK");

    std::vector<std::uint8_t> close_ack = build_client_packet(
        flow,
        1001,
        fin_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&close_ack[0], close_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK for close should be accepted");
    require(context.closed_flows.size() == 1, "close_flow should eventually emit close callback");
}

void test_incoming_rst_clears_flow() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> rst_packet = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    mirage_tcp::Ipv4Packet rst_ip;
    require(
        mirage_tcp::parse_ipv4_packet(&rst_packet[0], rst_packet.size(), &rst_ip) == mirage_tcp::ErrorCode::Ok,
        "ipv4 parse should succeed");
    mirage_tcp::TcpSegment rst_segment;
    require(
        mirage_tcp::parse_tcp_segment(rst_ip.payload, &rst_segment) == mirage_tcp::ErrorCode::Ok,
        "tcp parse should succeed");
    rst_segment.rst = true;
    rst_ip.payload = mirage_tcp::serialize_tcp_segment(rst_segment);
    require(
        mirage_tcp::serialize_ipv4_packet(rst_ip, &rst_packet) == mirage_tcp::ErrorCode::Ok,
        "RST packet serialization should succeed");

    require(mirage_tcp.handle_incoming_ip_packet(&rst_packet[0], rst_packet.size()) == mirage_tcp::ErrorCode::Ok, "incoming RST should be accepted");
    require(context.reset_flows.size() == 1, "incoming RST should emit reset callback");
}

void test_invalid_ack_resets_existing_flow() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    mirage_tcp::ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == mirage_tcp::ErrorCode::Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 100,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == mirage_tcp::ErrorCode::HandshakeFinalAckExpected,
        "invalid final ACK should fail");
    require(context.reset_flows.size() == 1, "invalid final ACK should reset flow");
    require(context.downstream_packets.size() == 2, "invalid final ACK should generate reset packet");
    mirage_tcp::TcpSegment reset = parse_tcp_from_ip(context.downstream_packets[1]);
    require(reset.rst, "invalid final ACK response should be RST");
}

}  // namespace

int main() {
    std::vector<TestCase> tests;
    tests.push_back(TestCase{"ipv4_roundtrip", test_ipv4_roundtrip});
    tests.push_back(TestCase{"syn_generates_downstream_syn_ack", test_syn_generates_downstream_syn_ack});
    tests.push_back(TestCase{"final_ack_completes_handshake", test_final_ack_completes_handshake});
    tests.push_back(TestCase{"payload_is_reported_and_acked", test_payload_is_reported_and_acked});
    tests.push_back(TestCase{"fin_generates_fin_ack_and_close_event", test_fin_generates_fin_ack_and_close_event});
    tests.push_back(TestCase{"invalid_flow_reports_error", test_invalid_flow_reports_error});
    tests.push_back(TestCase{"send_downstream_payload_generates_data_segment", test_send_downstream_payload_generates_data_segment});
    tests.push_back(TestCase{"close_flow_generates_fin_ack_and_close_event", test_close_flow_generates_fin_ack_and_close_event});
    tests.push_back(TestCase{"incoming_rst_clears_flow", test_incoming_rst_clears_flow});
    tests.push_back(TestCase{"invalid_ack_resets_existing_flow", test_invalid_ack_resets_existing_flow});

    for (std::size_t i = 0; i < tests.size(); ++i) {
        try {
            tests[i].run();
            std::cout << "[PASS] " << tests[i].name << std::endl;
        } catch (const std::exception& error) {
            std::cerr << "[FAIL] " << tests[i].name << ": " << error.what() << std::endl;
            return 1;
        }
    }

    std::cout << tests.size() << " tests passed" << std::endl;
    return 0;
}

