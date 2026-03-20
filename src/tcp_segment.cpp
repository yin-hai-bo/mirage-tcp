#include "mirage_tcp/tcp_segment.h"
#include "mirage_tcp/tcp_head.h"

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

TcpSegment::TcpSegment()
    : source_port(0),
      destination_port(0),
      sequence_number(0),
      acknowledgment_number(0),
      window_size(0),
      syn(false),
      ack(false),
      fin(false),
      rst(false) {}

error_code_t parse_tcp_segment(
    const void* bytes,
    size_t byte_count,
    TcpSegment& out_segment) {
    const size_t TCP_HEADER_LENGTH_BYTES = sizeof(TcpHead);
    if (byte_count < TCP_HEADER_LENGTH_BYTES) {
        return ErrorCode::PacketTooShort;
    }

    const uint8_t* raw_bytes = static_cast<const uint8_t*>(bytes);
    assert(reinterpret_cast<std::uintptr_t>(raw_bytes) % alignof(TcpHead) == 0U);

    const TcpHead* tcp_head = reinterpret_cast<const TcpHead*>(raw_bytes);
    const uint8_t data_offset_words =
        static_cast<uint8_t>(tcp_head->data_offset_reserved >> 4);
    if (data_offset_words < 5) {
        return ErrorCode::InvalidTcpDataOffset;
    }

    const size_t header_length = static_cast<size_t>(data_offset_words) * 4U;
    if (header_length > byte_count) {
        return ErrorCode::TcpHeaderTooLong;
    }

    out_segment.source_port = ntohs(tcp_head->source_port);
    out_segment.destination_port = ntohs(tcp_head->destination_port);
    out_segment.sequence_number = ntohl(tcp_head->sequence_number);
    out_segment.acknowledgment_number = ntohl(tcp_head->acknowledgment_number);
    out_segment.window_size = ntohs(tcp_head->window_size);

    const uint8_t flags = tcp_head->flags;
    out_segment.fin = (flags & 0x01U) != 0;
    out_segment.syn = (flags & 0x02U) != 0;
    out_segment.rst = (flags & 0x04U) != 0;
    out_segment.ack = (flags & 0x10U) != 0;

    out_segment.payload.assign(
        raw_bytes + static_cast<std::ptrdiff_t>(header_length),
        raw_bytes + static_cast<std::ptrdiff_t>(byte_count));
    return ErrorCode::Ok;
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

    uint8_t flags = 0;
    if (segment.fin) {
        flags |= 0x01U;
    }
    if (segment.syn) {
        flags |= 0x02U;
    }
    if (segment.rst) {
        flags |= 0x04U;
    }
    if (segment.ack) {
        flags |= 0x10U;
    }
    tcp_head.flags = flags;

    write_u16_be(segment.window_size, tcp_head_bytes, offsetof(TcpHead, window_size));
    write_u16_be(0, tcp_head_bytes, offsetof(TcpHead, checksum));
    write_u16_be(0, tcp_head_bytes, offsetof(TcpHead, urgent_pointer));

    std::memcpy(&bytes[0], tcp_head_bytes, sizeof(tcp_head));

    for (size_t i = 0; i < segment.payload.size(); ++i) {
        bytes[header_length + i] = segment.payload[i];
    }

    return bytes;
}

}  // namespace mirage_tcp

