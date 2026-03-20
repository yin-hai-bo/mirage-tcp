#include "mirage_tcp/tcp_segment.h"
#include "mirage_tcp/tcp_head.h"

#include <cstring>

namespace mirage_tcp {

namespace {

uint16_t read_u16_be(const uint8_t* bytes, size_t offset) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[offset]) << 8) |
        static_cast<uint16_t>(bytes[offset + 1]));
}

uint32_t read_u32_be(const uint8_t* bytes, size_t offset) {
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

void write_u16_be(uint16_t value, std::vector<uint8_t>* bytes, size_t offset) {
    (*bytes)[offset] = static_cast<uint8_t>((value >> 8) & 0xff);
    (*bytes)[offset + 1] = static_cast<uint8_t>(value & 0xff);
}

void write_u16_be(uint16_t value, uint8_t* bytes, size_t offset) {
    bytes[offset] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[offset + 1] = static_cast<uint8_t>(value & 0xff);
}

void write_u32_be(uint32_t value, std::vector<uint8_t>* bytes, size_t offset) {
    (*bytes)[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    (*bytes)[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    (*bytes)[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    (*bytes)[offset + 3] = static_cast<uint8_t>(value & 0xff);
}

void write_u32_be(uint32_t value, uint8_t* bytes, size_t offset) {
    bytes[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    bytes[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    bytes[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[offset + 3] = static_cast<uint8_t>(value & 0xff);
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
    TcpSegment& segment) {
    const size_t TCP_HEADER_LENGTH_BYTES = sizeof(TcpHead);
    if (byte_count < TCP_HEADER_LENGTH_BYTES) {
        return ErrorCode::PacketTooShort;
    }

    const uint8_t* raw_bytes = static_cast<const uint8_t*>(bytes);
    TcpHead tcp_head;
    std::memcpy(&tcp_head, raw_bytes, sizeof(tcp_head));

    const uint8_t data_offset_words = static_cast<uint8_t>(tcp_head.data_offset_reserved >> 4);
    if (data_offset_words < 5) {
        return ErrorCode::InvalidTcpDataOffset;
    }

    const size_t header_length = static_cast<size_t>(data_offset_words) * 4U;
    if (header_length > byte_count) {
        return ErrorCode::TcpHeaderTooLong;
    }

    TcpSegment parsed;
    const uint8_t* tcp_head_bytes = reinterpret_cast<const uint8_t*>(&tcp_head);
    parsed.source_port = read_u16_be(tcp_head_bytes, offsetof(TcpHead, source_port));
    parsed.destination_port = read_u16_be(tcp_head_bytes, offsetof(TcpHead, destination_port));
    parsed.sequence_number = read_u32_be(tcp_head_bytes, offsetof(TcpHead, sequence_number));
    parsed.acknowledgment_number = read_u32_be(tcp_head_bytes, offsetof(TcpHead, acknowledgment_number));
    parsed.window_size = read_u16_be(tcp_head_bytes, offsetof(TcpHead, window_size));

    const uint8_t flags = tcp_head.flags;
    parsed.fin = (flags & 0x01U) != 0;
    parsed.syn = (flags & 0x02U) != 0;
    parsed.rst = (flags & 0x04U) != 0;
    parsed.ack = (flags & 0x10U) != 0;

    parsed.payload.assign(
        raw_bytes + static_cast<std::ptrdiff_t>(header_length),
        raw_bytes + static_cast<std::ptrdiff_t>(byte_count));
    segment = parsed;
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

