#include <cstddef>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "mirage_tcp/connection_info.h"
#include "mirage_tcp/error_code.h"
#include "mirage_tcp/mirage_tcp.hpp"

#include "connection_info.hpp"
#include "ipv4_packet.h"
#include "tcp_segment.h"
#include "test_harness.h"

void append_checksum_tests(std::vector<TestCase>* tests);

namespace {

using mirage_tcp::TcpSegment;
using mirage_tcp::ConnectionInfo;

struct CallbackContext {
    std::vector<std::vector<std::uint8_t> > downstream_packets;
    std::vector<ConnectionInfo> handshakes;
    std::vector<std::vector<std::uint8_t> > payloads;
    std::vector<ConnectionInfo> closed_flows;
    std::vector<ConnectionInfo> reset_flows;
};

void on_downstream_ip_packet_generated(void* user_data, const void* ip_packet, std::size_t ip_packet_size) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(ip_packet);
    context->downstream_packets.push_back(
        std::vector<std::uint8_t>(bytes, bytes + static_cast<std::ptrdiff_t>(ip_packet_size)));
}

in_addr make_ipv4_address(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    in_addr address;
    const std::uint8_t bytes[4] = {a, b, c, d};
    std::memcpy(&address, bytes, sizeof(address));
    return address;
}

in6_addr make_ipv6_address(const std::uint8_t (&bytes)[16]) {
    in6_addr address;
    std::memcpy(&address, bytes, sizeof(address));
    return address;
}

bool same_ipv4_address(const in_addr& left, const in_addr& right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

bool same_ipv6_address(const in6_addr& left, const in6_addr& right) {
    return std::memcmp(&left, &right, sizeof(left)) == 0;
}

void on_tcp_handshake_completed(void* user_data, const ConnectionInfo * connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->handshakes.push_back(*connection_info);
}

void on_tcp_payload_received(
    void* user_data,
    const ConnectionInfo *,
    const void* payload,
    std::size_t payload_size) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    const std::uint8_t* bytes = static_cast<const std::uint8_t*>(payload);
    context->payloads.push_back(
        std::vector<std::uint8_t>(bytes, bytes + static_cast<std::ptrdiff_t>(payload_size)));
}

void on_tcp_connection_closed(void* user_data, const ConnectionInfo * connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->closed_flows.push_back(*connection_info);
}

void on_tcp_connection_reset(void* user_data, const ConnectionInfo * connection_info) {
    CallbackContext* context = static_cast<CallbackContext*>(user_data);
    context->reset_flows.push_back(*connection_info);
}

mirage_tcp::MirageTcp make_mirage_tcp(CallbackContext* context) {
    mirage_tcp_callbacks_t callbacks = {};
    callbacks.user_data = context;
    callbacks.on_downstream_ip_packet_generated = on_downstream_ip_packet_generated;
    callbacks.on_tcp_handshake_completed = on_tcp_handshake_completed;
    callbacks.on_tcp_payload_received = on_tcp_payload_received;
    callbacks.on_tcp_connection_closed = on_tcp_connection_closed;
    callbacks.on_tcp_connection_reset = on_tcp_connection_reset;
    return mirage_tcp::MirageTcp(callbacks);
}

mirage_tcp_object make_mirage_tcp_c(CallbackContext* context) {
    mirage_tcp_callbacks_t callbacks = {};
    callbacks.user_data = context;
    callbacks.on_downstream_ip_packet_generated = on_downstream_ip_packet_generated;
    callbacks.on_tcp_handshake_completed = on_tcp_handshake_completed;
    callbacks.on_tcp_payload_received = on_tcp_payload_received;
    callbacks.on_tcp_connection_closed = on_tcp_connection_closed;
    callbacks.on_tcp_connection_reset = on_tcp_connection_reset;

    mirage_tcp_object instance = nullptr;
    require(mirage_tcp_create(&callbacks, &instance) == MTE_Ok, "mirage_tcp_create should succeed");
    require(instance != nullptr, "mirage_tcp_create should return non-null handle");
    return instance;
}

ConnectionInfo make_flow() {
    ConnectionInfo result;
    mirage_tcp_set_connection_info_v4(
        &make_ipv4_address(10, 0, 0, 1),
        &make_ipv4_address(93, 184, 216, 34),
        49152,
        443,
        &result);
    return result;
}

std::vector<std::uint8_t> build_client_packet(
    const ConnectionInfo& flow,
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
    TcpSegment::FlagsBuilder flags_builder;
    if (syn) {
        flags_builder.set_syn();
    }
    if (ack) {
        flags_builder.set_ack();
    }
    if (fin) {
        flags_builder.set_fin();
    }
    segment.flags = flags_builder.flags();
    segment.payload = payload;

    const std::vector<std::uint8_t> tcp_bytes = mirage_tcp::serialize_tcp_segment(segment);
    mirage_tcp::Ip4Head head = {};
    head.version_ihl = 0x45;
    head.ttl = 64;
    head.protocol = mirage_tcp::IP_PROTOCOL_TCP;
    std::memcpy(&head.source_address, &flow.client_ip.ipv4, sizeof(head.source_address));
    std::memcpy(&head.destination_address, &flow.server_ip.ipv4, sizeof(head.destination_address));
    std::vector<std::uint8_t> bytes;
    require(
        mirage_tcp::serialize_ipv4_packet(head, &tcp_bytes[0], tcp_bytes.size(), &bytes) == MTE_Ok,
        "client packet serialization should succeed");
    return bytes;
}

mirage_tcp::TcpSegment parse_tcp_from_ip(const std::vector<std::uint8_t>& packet_bytes) {
    require(packet_bytes.size() >= sizeof(mirage_tcp::Ip4Head), "ipv4 packet should contain fixed header");
    const mirage_tcp::Ip4Head* head = reinterpret_cast<const mirage_tcp::Ip4Head*>(&packet_bytes[0]);
    const std::size_t header_length = static_cast<std::size_t>(head->version_ihl & 0x0fU) * 4U;
    require(header_length >= sizeof(mirage_tcp::Ip4Head), "ipv4 header length should be valid");
    require(packet_bytes.size() >= header_length, "ipv4 packet should contain full header");

    mirage_tcp::TcpSegment segment;
    require(
        mirage_tcp::parse_tcp_segment(&packet_bytes[header_length], packet_bytes.size() - header_length, segment) == MTE_Ok,
        "tcp parse should succeed");
    return segment;
}

mirage_tcp::TcpSegment establish_flow_via_c_api(
    mirage_tcp_object instance,
    CallbackContext* context,
    const ConnectionInfo& flow) {
    std::vector<std::uint8_t> syn_packet = build_client_packet(
        flow,
        1000,
        0,
        true,
        false,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp_handle_incoming_ip_packet(instance, &syn_packet[0], syn_packet.size()) == MTE_Ok,
        "C API SYN should be accepted");
    require(context->downstream_packets.size() == 1, "C API SYN should generate one downstream packet");

    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context->downstream_packets[0]);
    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp_handle_incoming_ip_packet(instance, &final_ack[0], final_ack.size()) == MTE_Ok,
        "C API final ACK should be accepted");
    return syn_ack;
}

void test_ipv4_roundtrip() {
    mirage_tcp::Ip4Head head = {};
    const in_addr source_address = make_ipv4_address(10, 0, 0, 1);
    const in_addr destination_address = make_ipv4_address(10, 0, 0, 2);
    head.version_ihl = 0x45;
    head.ttl = 42;
    head.protocol = mirage_tcp::IP_PROTOCOL_TCP;
    std::memcpy(&head.source_address, &source_address, sizeof(head.source_address));
    std::memcpy(&head.destination_address, &destination_address, sizeof(head.destination_address));
    std::vector<std::uint8_t> payload(5, 0x11);

    std::vector<std::uint8_t> bytes;
    require(
        mirage_tcp::serialize_ipv4_packet(head, &payload[0], payload.size(), &bytes) == MTE_Ok,
        "ipv4 serialize should succeed");

    require(bytes.size() >= sizeof(mirage_tcp::Ip4Head), "serialized ipv4 packet should contain fixed header");
    const mirage_tcp::Ip4Head* parsed = reinterpret_cast<const mirage_tcp::Ip4Head*>(&bytes[0]);
    require(
        std::memcmp(&parsed->source_address, &head.source_address, sizeof(head.source_address)) == 0,
        "ipv4 source mismatch");
    require(
        std::memcmp(&parsed->destination_address, &head.destination_address, sizeof(head.destination_address)) == 0,
        "ipv4 destination mismatch");
    require(parsed->protocol == head.protocol, "ipv4 protocol mismatch");
    require(parsed->ttl == head.ttl, "ipv4 ttl mismatch");
    const std::size_t header_length = static_cast<std::size_t>(parsed->version_ihl & 0x0fU) * 4U;
    require(bytes.size() - header_length == payload.size(), "ipv4 payload size mismatch");
    require(std::memcmp(&bytes[header_length], &payload[0], payload.size()) == 0, "ipv4 payload mismatch");
}

void test_connection_info_equal_checks_ports_before_ip_for_ipv4() {
    ConnectionInfo left = make_flow();
    ConnectionInfo right;
    mirage_tcp_set_connection_info_v4(
        &make_ipv4_address(10, 0, 0, 99),
        &make_ipv4_address(93, 184, 216, 99),
        static_cast<std::uint16_t>(left.client_port + 1),
        left.server_port,
        &right);

    require(!(left == right), "ipv4 equality should fail when client port differs");

    ConnectionInfo different_server_port;
    mirage_tcp_set_connection_info_v4(
        &make_ipv4_address(10, 0, 0, 99),
        &make_ipv4_address(93, 184, 216, 99),
        left.client_port,
        static_cast<std::uint16_t>(left.server_port + 1),
        &different_server_port);

    require(!(left == different_server_port), "ipv4 equality should fail when server port differs");
}

void test_connection_info_equal_uses_ipv4_s_addr() {
    ConnectionInfo left = make_flow();
    ConnectionInfo right = make_flow();

    require(left == right, "identical ipv4 flows should compare equal");

    ConnectionInfo different_client_ip;
    mirage_tcp_set_connection_info_v4(
        &make_ipv4_address(10, 0, 0, 2),
        &right.server_ip.ipv4,
        right.client_port,
        right.server_port,
        &different_client_ip
    );
    require(!(left == different_client_ip), "ipv4 equality should compare client address by s_addr");

    ConnectionInfo different_server_ip;
    mirage_tcp_set_connection_info_v4(
        &right.client_ip.ipv4,
        &make_ipv4_address(93, 184, 216, 35),
        right.client_port,
        right.server_port,
        &different_server_ip
    );
    require(!(left == different_server_ip), "ipv4 equality should compare server address by s_addr");
}

void test_connection_info_equal_uses_memcmp_for_ipv6() {
    const std::uint8_t client_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t server_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2};
    const std::uint8_t different_server_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3};

    ConnectionInfo left;
    mirage_tcp_set_connection_info_v6(
        &make_ipv6_address(client_bytes),
        &make_ipv6_address(server_bytes),
        12345,
        443,
        &left
    );

    ConnectionInfo right = left;
    require(left == right, "identical ipv6 flows should compare equal");

    ConnectionInfo different_server_ip;
    mirage_tcp_set_connection_info_v6(
        &make_ipv6_address(client_bytes),
        &make_ipv6_address(different_server_bytes),
        12345,
        443,
        &different_server_ip
    );
    require(!(left == different_server_ip), "ipv6 equality should compare full address bytes");
}

void test_connection_info_hash_and_equal_work_with_unordered_map() {
    ConnectionInfo flow = make_flow();
    std::unordered_map<ConnectionInfo, int, mirage_tcp::ConnectionInfoHash, mirage_tcp::ConnectionInfoEqual> values;
    values.insert(std::make_pair(flow, 7));

    const ConnectionInfo same_flow = flow;
    require(values.find(same_flow) != values.end(), "unordered_map should find equivalent connection info");
    require(values.find(same_flow)->second == 7, "unordered_map should preserve stored value");

    ConnectionInfo different_port;
    mirage_tcp_set_connection_info_v4(
        &flow.client_ip.ipv4,
        &flow.server_ip.ipv4,
        static_cast<std::uint16_t>(flow.client_port + 1),
        flow.server_port,
        &different_port
    );
    require(values.find(different_port) == values.end(), "unordered_map should not match different port");
}

void test_connection_info_setters_ignore_null_arguments() {
    ConnectionInfo ipv4_target;
    std::memset(&ipv4_target, 0x5a, sizeof(ipv4_target));
    const ConnectionInfo ipv4_before = ipv4_target;
    const in_addr client_ipv4 = make_ipv4_address(10, 0, 0, 1);
    const in_addr server_ipv4 = make_ipv4_address(93, 184, 216, 34);

    mirage_tcp_set_connection_info_v4(nullptr, &server_ipv4, 12345, 443, &ipv4_target);
    require(std::memcmp(&ipv4_target, &ipv4_before, sizeof(ipv4_target)) == 0, "null client ipv4 should leave target unchanged");

    mirage_tcp_set_connection_info_v4(&client_ipv4, nullptr, 12345, 443, &ipv4_target);
    require(std::memcmp(&ipv4_target, &ipv4_before, sizeof(ipv4_target)) == 0, "null server ipv4 should leave target unchanged");

    mirage_tcp_set_connection_info_v4(&client_ipv4, &server_ipv4, 12345, 443, nullptr);

    ConnectionInfo ipv6_target;
    std::memset(&ipv6_target, 0x6b, sizeof(ipv6_target));
    const ConnectionInfo ipv6_before = ipv6_target;
    const std::uint8_t client_ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t server_ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2};
    const in6_addr client_ipv6 = make_ipv6_address(client_ipv6_bytes);
    const in6_addr server_ipv6 = make_ipv6_address(server_ipv6_bytes);

    mirage_tcp_set_connection_info_v6(nullptr, &server_ipv6, 12345, 443, &ipv6_target);
    require(std::memcmp(&ipv6_target, &ipv6_before, sizeof(ipv6_target)) == 0, "null client ipv6 should leave target unchanged");

    mirage_tcp_set_connection_info_v6(&client_ipv6, nullptr, 12345, 443, &ipv6_target);
    require(std::memcmp(&ipv6_target, &ipv6_before, sizeof(ipv6_target)) == 0, "null server ipv6 should leave target unchanged");

    mirage_tcp_set_connection_info_v6(&client_ipv6, &server_ipv6, 12345, 443, nullptr);
}

void test_connection_info_setters_populate_expected_fields() {
    const in_addr client_ipv4 = make_ipv4_address(10, 0, 0, 1);
    const in_addr server_ipv4 = make_ipv4_address(93, 184, 216, 34);
    ConnectionInfo ipv4_target;
    mirage_tcp_set_connection_info_v4(&client_ipv4, &server_ipv4, 12345, 443, &ipv4_target);

    require(ipv4_target.ip_ver == 4, "ipv4 setter should set ip version");
    require(ipv4_target.client_port == 12345, "ipv4 setter should set client port");
    require(ipv4_target.server_port == 443, "ipv4 setter should set server port");
    require(same_ipv4_address(ipv4_target.client_ip.ipv4, client_ipv4), "ipv4 setter should set client address");
    require(same_ipv4_address(ipv4_target.server_ip.ipv4, server_ipv4), "ipv4 setter should set server address");

    const std::uint8_t client_ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::uint8_t server_ipv6_bytes[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2};
    const in6_addr client_ipv6 = make_ipv6_address(client_ipv6_bytes);
    const in6_addr server_ipv6 = make_ipv6_address(server_ipv6_bytes);
    ConnectionInfo ipv6_target;
    mirage_tcp_set_connection_info_v6(&client_ipv6, &server_ipv6, 23456, 8443, &ipv6_target);

    require(ipv6_target.ip_ver == 6, "ipv6 setter should set ip version");
    require(ipv6_target.client_port == 23456, "ipv6 setter should set client port");
    require(ipv6_target.server_port == 8443, "ipv6 setter should set server port");
    require(same_ipv6_address(ipv6_target.client_ip.ipv6, client_ipv6), "ipv6 setter should set client address");
    require(same_ipv6_address(ipv6_target.server_ip.ipv6, server_ipv6), "ipv6 setter should set server address");
}

void test_syn_generates_downstream_syn_ack() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    require(context.downstream_packets.size() == 1, "SYN should generate one downstream packet");
    require(context.handshakes.empty(), "handshake should not complete after SYN only");

    mirage_tcp::TcpSegment response = parse_tcp_from_ip(context.downstream_packets[0]);
    require(response.is_syn(), "response should contain SYN");
    require(response.is_ack(), "response should contain ACK");
    require(!response.is_fin(), "response should not contain FIN");
    require(response.acknowledgment_number == 1001, "SYN+ACK must acknowledge client SYN");
}

void test_final_ack_completes_handshake() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");

    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);
    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");
    require(context.handshakes.size() == 1, "handshake callback should fire once");
    require(context.handshakes[0].client_port == flow.client_port, "handshake flow client port mismatch");
    require(context.handshakes[0].ip_ver == 4, "handshake flow ip version mismatch");
    require(same_ipv4_address(context.handshakes[0].client_ip.ipv4, flow.client_ip.ipv4), "handshake flow client ip mismatch");
}

void test_payload_is_reported_and_acked() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");

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
    require(mirage_tcp.handle_incoming_ip_packet(&payload_packet[0], payload_packet.size()) == MTE_Ok, "payload should be accepted");

    require(context.payloads.size() == 1, "payload callback should fire once");
    require(context.payloads[0] == payload, "payload callback content mismatch");
    require(context.downstream_packets.size() == 2, "payload should generate one ACK packet");
    mirage_tcp::TcpSegment ack_only = parse_tcp_from_ip(context.downstream_packets[1]);
    require(ack_only.is_ack(), "payload response should ACK");
    require(ack_only.acknowledgment_number == 1003, "payload ACK number mismatch");
}

void test_fin_generates_fin_ack_and_close_event() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> fin_packet = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        true,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&fin_packet[0], fin_packet.size()) == MTE_Ok, "FIN should be accepted");
    require(context.downstream_packets.size() == 2, "FIN should generate one FIN+ACK");
    mirage_tcp::TcpSegment fin_ack = parse_tcp_from_ip(context.downstream_packets[1]);
    require(fin_ack.is_fin(), "response to FIN should include FIN");
    require(fin_ack.is_ack(), "response to FIN should include ACK");

    std::vector<std::uint8_t> final_close_ack = build_client_packet(
        flow,
        1002,
        fin_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp.handle_incoming_ip_packet(&final_close_ack[0], final_close_ack.size()) == MTE_Ok,
        "final close ACK should be accepted");
    require(context.closed_flows.size() == 1, "close callback should fire once");
}

void test_invalid_flow_reports_error() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> ack_packet = build_client_packet(
        flow,
        1001,
        2000,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&ack_packet[0], ack_packet.size()) == MTE_FlowNotFound, "unknown flow should be handled with reset");
    require(context.downstream_packets.size() == 1, "unknown flow should generate one reset packet");
    mirage_tcp::TcpSegment reset = parse_tcp_from_ip(context.downstream_packets[0]);
    require(reset.is_rst(), "unknown flow response should be RST");
}

void test_null_packet_returns_invalid_argument_without_error_callback() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);

    require(
        mirage_tcp.handle_incoming_ip_packet(nullptr, 20) == MTE_InvalidArgument,
        "null packet should return invalid argument");
}

void test_short_packet_returns_packet_too_short_without_error_callback() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    const std::uint8_t packet[19] = {};

    require(
        mirage_tcp.handle_incoming_ip_packet(packet, sizeof(packet)) == MTE_PacketTooShort,
        "short packet should return packet too short");
}

void test_ipv6_tcp_packet_reports_unsupported() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);

    std::vector<std::uint8_t> ipv6_packet(40, 0);
    ipv6_packet[0] = 0x60;
    ipv6_packet[6] = mirage_tcp::IP_PROTOCOL_TCP;

    require(
        mirage_tcp.handle_incoming_ip_packet(&ipv6_packet[0], ipv6_packet.size()) == MTE_Unsupported,
        "ipv6 tcp packet should report unsupported");
}

void test_ipv4_non_tcp_packet_reports_is_not_tcp() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> payload(4, 0);
    mirage_tcp::Ip4Head head = {};
    head.version_ihl = 0x45;
    head.ttl = 64;
    head.protocol = 17;
    std::memcpy(&head.source_address, &flow.client_ip.ipv4, sizeof(head.source_address));
    std::memcpy(&head.destination_address, &flow.server_ip.ipv4, sizeof(head.destination_address));

    std::vector<std::uint8_t> packet;
    require(
        mirage_tcp::serialize_ipv4_packet(head, &payload[0], payload.size(), &packet) == MTE_Ok,
        "ipv4 non-tcp packet serialization should succeed");
    require(
        mirage_tcp.handle_incoming_ip_packet(&packet[0], packet.size()) == MTE_IsNotTcp,
        "ipv4 non-tcp packet should report is not tcp");
}

void test_send_downstream_payload_generates_data_segment() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> payload;
    payload.push_back('p');
    payload.push_back('o');
    payload.push_back('n');
    payload.push_back('g');
    require(
        mirage_tcp.send_downstream_tcp_payload(flow, &payload[0], payload.size()) == MTE_Ok,
        "send_downstream_tcp_payload should succeed");
    require(context.downstream_packets.size() == 2, "downstream payload should generate one packet");
    mirage_tcp::TcpSegment response = parse_tcp_from_ip(context.downstream_packets[1]);
    require(response.is_ack(), "downstream payload should carry ACK");
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
        mirage_tcp.handle_incoming_ip_packet(&payload_ack[0], payload_ack.size()) == MTE_Ok,
        "client ACK for downstream payload should be accepted");
}

void test_close_flow_generates_fin_ack_and_close_event() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");

    require(mirage_tcp.close_flow(flow) == MTE_Ok, "close_flow should succeed");
    require(context.downstream_packets.size() == 2, "close_flow should generate one FIN+ACK");
    mirage_tcp::TcpSegment fin_ack = parse_tcp_from_ip(context.downstream_packets[1]);
    require(fin_ack.is_fin(), "close_flow response should include FIN");
    require(fin_ack.is_ack(), "close_flow response should include ACK");

    std::vector<std::uint8_t> close_ack = build_client_packet(
        flow,
        1001,
        fin_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&close_ack[0], close_ack.size()) == MTE_Ok, "final ACK for close should be accepted");
    require(context.closed_flows.size() == 1, "close_flow should eventually emit close callback");
}

void test_incoming_rst_clears_flow() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
    mirage_tcp::TcpSegment syn_ack = parse_tcp_from_ip(context.downstream_packets[0]);

    std::vector<std::uint8_t> final_ack = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_Ok, "final ACK should be accepted");

    std::vector<std::uint8_t> rst_packet = build_client_packet(
        flow,
        1001,
        syn_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(rst_packet.size() >= sizeof(mirage_tcp::Ip4Head), "rst packet should contain fixed header");
    const mirage_tcp::Ip4Head* rst_ip = reinterpret_cast<const mirage_tcp::Ip4Head*>(&rst_packet[0]);
    const std::size_t rst_header_length = static_cast<std::size_t>(rst_ip->version_ihl & 0x0fU) * 4U;
    mirage_tcp::TcpSegment rst_segment;
    require(
        mirage_tcp::parse_tcp_segment(&rst_packet[rst_header_length], rst_packet.size() - rst_header_length, rst_segment) == MTE_Ok,
        "tcp parse should succeed");
    rst_segment.flags = TcpSegment::FlagsBuilder().set_rst().flags();
    const std::vector<std::uint8_t> rst_payload = mirage_tcp::serialize_tcp_segment(rst_segment);
    mirage_tcp::Ip4Head rst_head = *rst_ip;
    require(
        mirage_tcp::serialize_ipv4_packet(rst_head, &rst_payload[0], rst_payload.size(), &rst_packet) == MTE_Ok,
        "RST packet serialization should succeed");

    require(mirage_tcp.handle_incoming_ip_packet(&rst_packet[0], rst_packet.size()) == MTE_Ok, "incoming RST should be accepted");
    require(context.reset_flows.size() == 1, "incoming RST should emit reset callback");
}

void test_invalid_ack_resets_existing_flow() {
    CallbackContext context;
    mirage_tcp::MirageTcp mirage_tcp = make_mirage_tcp(&context);
    ConnectionInfo flow = make_flow();

    std::vector<std::uint8_t> syn_packet = build_client_packet(flow, 1000, 0, true, false, false, std::vector<std::uint8_t>());
    require(mirage_tcp.handle_incoming_ip_packet(&syn_packet[0], syn_packet.size()) == MTE_Ok, "SYN should be accepted");
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
        mirage_tcp.handle_incoming_ip_packet(&final_ack[0], final_ack.size()) == MTE_HandshakeFinalAckExpected,
        "invalid final ACK should fail");
    require(context.reset_flows.size() == 1, "invalid final ACK should reset flow");
    require(context.downstream_packets.size() == 2, "invalid final ACK should generate reset packet");
    mirage_tcp::TcpSegment reset = parse_tcp_from_ip(context.downstream_packets[1]);
    require(reset.is_rst(), "invalid final ACK response should be RST");
}

void test_c_api_create_validates_arguments() {
    mirage_tcp_callbacks_t callbacks = {};
    mirage_tcp_object instance = nullptr;

    require(
        mirage_tcp_create(nullptr, &instance) == MTE_InvalidArgument,
        "mirage_tcp_create should reject null callbacks");
    require(
        mirage_tcp_create(&callbacks, nullptr) == MTE_InvalidArgument,
        "mirage_tcp_create should reject null result");
}

void test_c_api_destroy_accepts_null() {
    mirage_tcp_destroy(nullptr);
}

void test_c_api_handle_incoming_ip_packet_completes_handshake() {
    CallbackContext context;
    const ConnectionInfo flow = make_flow();
    const mirage_tcp_object instance = make_mirage_tcp_c(&context);

    const mirage_tcp::TcpSegment syn_ack = establish_flow_via_c_api(instance, &context, flow);

    require(syn_ack.is_syn(), "C API handshake response should contain SYN");
    require(syn_ack.is_ack(), "C API handshake response should contain ACK");
    require(context.handshakes.size() == 1, "C API handshake callback should fire once");
    require(context.handshakes[0].client_port == flow.client_port, "C API handshake flow client port mismatch");

    mirage_tcp_destroy(instance);
}

void test_c_api_send_downstream_payload_generates_data_segment() {
    CallbackContext context;
    const ConnectionInfo flow = make_flow();
    const mirage_tcp_object instance = make_mirage_tcp_c(&context);
    establish_flow_via_c_api(instance, &context, flow);

    const char payload[] = "pong";
    require(
        mirage_tcp_send_downstream_tcp_payload(instance, &flow, payload, sizeof(payload) - 1) == MTE_Ok,
        "C API send_downstream_tcp_payload should succeed");
    require(context.downstream_packets.size() == 2, "C API downstream payload should generate one packet");

    const mirage_tcp::TcpSegment response = parse_tcp_from_ip(context.downstream_packets[1]);
    require(response.is_ack(), "C API downstream payload should carry ACK");
    require(
        response.payload == std::vector<std::uint8_t>(payload, payload + sizeof(payload) - 1),
        "C API downstream payload content mismatch");

    std::vector<std::uint8_t> payload_ack = build_client_packet(
        flow,
        1001,
        response.sequence_number + static_cast<std::uint32_t>(sizeof(payload) - 1),
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp_handle_incoming_ip_packet(instance, &payload_ack[0], payload_ack.size()) == MTE_Ok,
        "C API downstream payload ACK should be accepted");

    mirage_tcp_destroy(instance);
}

void test_c_api_close_flow_generates_fin_ack_and_close_event() {
    CallbackContext context;
    const ConnectionInfo flow = make_flow();
    const mirage_tcp_object instance = make_mirage_tcp_c(&context);
    establish_flow_via_c_api(instance, &context, flow);

    require(
        mirage_tcp_close_flow(instance, &flow) == MTE_Ok,
        "C API close_flow should succeed");
    require(context.downstream_packets.size() == 2, "C API close_flow should generate one FIN+ACK");

    const mirage_tcp::TcpSegment fin_ack = parse_tcp_from_ip(context.downstream_packets[1]);
    require(fin_ack.is_fin(), "C API close_flow response should include FIN");
    require(fin_ack.is_ack(), "C API close_flow response should include ACK");

    std::vector<std::uint8_t> close_ack = build_client_packet(
        flow,
        1001,
        fin_ack.sequence_number + 1,
        false,
        true,
        false,
        std::vector<std::uint8_t>());
    require(
        mirage_tcp_handle_incoming_ip_packet(instance, &close_ack[0], close_ack.size()) == MTE_Ok,
        "C API final ACK for close should be accepted");
    require(context.closed_flows.size() == 1, "C API close_flow should emit close callback");

    mirage_tcp_destroy(instance);
}

void test_c_api_rejects_null_instance_and_connection_info() {
    CallbackContext context;
    const ConnectionInfo flow = make_flow();
    const std::uint8_t packet[20] = {};
    const mirage_tcp_object instance = make_mirage_tcp_c(&context);

    require(
        mirage_tcp_handle_incoming_ip_packet(nullptr, packet, sizeof(packet)) == MTE_InvalidArgument,
        "C API handle_incoming_ip_packet should reject null instance");
    require(
        mirage_tcp_send_downstream_tcp_payload(nullptr, &flow, "x", 1) == MTE_InvalidArgument,
        "C API send_downstream_tcp_payload should reject null instance");
    require(
        mirage_tcp_send_downstream_tcp_payload(instance, nullptr, "x", 1) == MTE_InvalidArgument,
        "C API send_downstream_tcp_payload should reject null connection info");
    require(
        mirage_tcp_close_flow(nullptr, &flow) == MTE_InvalidArgument,
        "C API close_flow should reject null instance");
    require(
        mirage_tcp_close_flow(instance, nullptr) == MTE_InvalidArgument,
        "C API close_flow should reject null connection info");

    mirage_tcp_destroy(instance);
}

}  // namespace

int main() {
    std::vector<TestCase> tests;
    tests.push_back(TestCase{"ipv4_roundtrip", test_ipv4_roundtrip});
    tests.push_back(TestCase{"connection_info_equal_checks_ports_before_ip_for_ipv4", test_connection_info_equal_checks_ports_before_ip_for_ipv4});
    tests.push_back(TestCase{"connection_info_equal_uses_ipv4_s_addr", test_connection_info_equal_uses_ipv4_s_addr});
    tests.push_back(TestCase{"connection_info_equal_uses_memcmp_for_ipv6", test_connection_info_equal_uses_memcmp_for_ipv6});
    tests.push_back(TestCase{"connection_info_hash_and_equal_work_with_unordered_map", test_connection_info_hash_and_equal_work_with_unordered_map});
    tests.push_back(TestCase{"connection_info_setters_ignore_null_arguments", test_connection_info_setters_ignore_null_arguments});
    tests.push_back(TestCase{"connection_info_setters_populate_expected_fields", test_connection_info_setters_populate_expected_fields});
    tests.push_back(TestCase{"syn_generates_downstream_syn_ack", test_syn_generates_downstream_syn_ack});
    tests.push_back(TestCase{"final_ack_completes_handshake", test_final_ack_completes_handshake});
    tests.push_back(TestCase{"payload_is_reported_and_acked", test_payload_is_reported_and_acked});
    tests.push_back(TestCase{"fin_generates_fin_ack_and_close_event", test_fin_generates_fin_ack_and_close_event});
    tests.push_back(TestCase{"invalid_flow_reports_error", test_invalid_flow_reports_error});
    tests.push_back(TestCase{"null_packet_returns_invalid_argument_without_error_callback", test_null_packet_returns_invalid_argument_without_error_callback});
    tests.push_back(TestCase{"short_packet_returns_packet_too_short_without_error_callback", test_short_packet_returns_packet_too_short_without_error_callback});
    tests.push_back(TestCase{"ipv6_tcp_packet_reports_unsupported", test_ipv6_tcp_packet_reports_unsupported});
    tests.push_back(TestCase{"ipv4_non_tcp_packet_reports_is_not_tcp", test_ipv4_non_tcp_packet_reports_is_not_tcp});
    tests.push_back(TestCase{"send_downstream_payload_generates_data_segment", test_send_downstream_payload_generates_data_segment});
    tests.push_back(TestCase{"close_flow_generates_fin_ack_and_close_event", test_close_flow_generates_fin_ack_and_close_event});
    tests.push_back(TestCase{"incoming_rst_clears_flow", test_incoming_rst_clears_flow});
    tests.push_back(TestCase{"invalid_ack_resets_existing_flow", test_invalid_ack_resets_existing_flow});
    tests.push_back(TestCase{"c_api_create_validates_arguments", test_c_api_create_validates_arguments});
    tests.push_back(TestCase{"c_api_destroy_accepts_null", test_c_api_destroy_accepts_null});
    tests.push_back(TestCase{"c_api_handle_incoming_ip_packet_completes_handshake", test_c_api_handle_incoming_ip_packet_completes_handshake});
    tests.push_back(TestCase{"c_api_send_downstream_payload_generates_data_segment", test_c_api_send_downstream_payload_generates_data_segment});
    tests.push_back(TestCase{"c_api_close_flow_generates_fin_ack_and_close_event", test_c_api_close_flow_generates_fin_ack_and_close_event});
    tests.push_back(TestCase{"c_api_rejects_null_instance_and_connection_info", test_c_api_rejects_null_instance_and_connection_info});
    append_checksum_tests(&tests);

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
