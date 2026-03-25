#include "tcp_segment.h"
#include "tcp_head.h"

#include <cassert>
#include <cstring>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

namespace mirage_tcp {

namespace {

void write_u16_be(uint16_t value, std::vector<uint8_t>* bytes, size_t offset) {
    const uint16_t network_value = htons(value);
    std::memcpy(bytes->data() + offset, &network_value, sizeof(network_value));
}

void write_u16_be(uint16_t value, uint8_t* bytes, size_t offset) {
    const uint16_t network_value = htons(value);
    std::memcpy(bytes + offset, &network_value, sizeof(network_value));
}

void write_u32_be(uint32_t value, std::vector<uint8_t>* bytes, size_t offset) {
    const uint32_t network_value = htonl(value);
    std::memcpy(bytes->data() + offset, &network_value, sizeof(network_value));
}

void write_u32_be(uint32_t value, uint8_t* bytes, size_t offset) {
    const uint32_t network_value = htonl(value);
    std::memcpy(bytes + offset, &network_value, sizeof(network_value));
}

}  // namespace

mirage_tcp_error_code_t parse_tcp_segment(
    const void* bytes,
    size_t byte_count,
    TcpSegment& out_segment)
{
    if (byte_count < sizeof(TcpHead)) {
        return MTE_PacketTooShort;
    }

    const uint8_t* raw_bytes = static_cast<const uint8_t*>(bytes);

    TcpHead tcp_head;
    std::memcpy(&tcp_head, bytes, sizeof(tcp_head));

    const size_t header_length = tcp_head.head_size();
    if (header_length < sizeof(TcpHead)) {
        return MTE_InvalidTcpDataOffset;
    }

    if (header_length > byte_count) {
        return MTE_TcpHeaderTooLong;
    }

    out_segment.source_port = ntohs(tcp_head.source_port);
    out_segment.destination_port = ntohs(tcp_head.destination_port);
    out_segment.sequence_number = ntohl(tcp_head.sequence_number);
    out_segment.acknowledgment_number = ntohl(tcp_head.acknowledgment_number);
    out_segment.window_size = ntohs(tcp_head.window_size);
    out_segment.flags = tcp_head.flags & 0x3fu;
    out_segment.payload.set(
        raw_bytes + static_cast<std::ptrdiff_t>(header_length),
        byte_count - header_length);
    return MTE_Ok;
}

std::vector<uint8_t> serialize_tcp_segment(const TcpSegment& segment) {
    const size_t TCP_HEADER_LENGTH_BYTES = sizeof(TcpHead);
    const size_t header_length = TCP_HEADER_LENGTH_BYTES;
    std::vector<uint8_t> bytes(header_length + segment.payload.size(), 0);

    TcpHead tcp_head = {};
    uint8_t* tcp_head_bytes = reinterpret_cast<uint8_t*>(&tcp_head);
    write_u16_be(segment.source_port, tcp_head_bytes, offsetof(TcpHead, source_port));
    write_u16_be(segment.destination_port, tcp_head_bytes, offsetof(TcpHead, destination_port));
    write_u32_be(segment.sequence_number, tcp_head_bytes, offsetof(TcpHead, sequence_number));
    write_u32_be(segment.acknowledgment_number, tcp_head_bytes, offsetof(TcpHead, acknowledgment_number));
    tcp_head.data_offset_reserved = static_cast<uint8_t>(5U << 4);

    tcp_head.flags = segment.flags;

    write_u16_be(segment.window_size, tcp_head_bytes, offsetof(TcpHead, window_size));
    write_u16_be(0, tcp_head_bytes, offsetof(TcpHead, checksum));
    write_u16_be(0, tcp_head_bytes, offsetof(TcpHead, urgent_pointer));

    std::memcpy(&bytes[0], tcp_head_bytes, sizeof(tcp_head));
    if (!segment.payload.empty()) {
        std::memcpy(
            bytes.data() + header_length,
            segment.payload.data(),
            segment.payload.size());
    }

    return bytes;
}

}  // namespace mirage_tcp
