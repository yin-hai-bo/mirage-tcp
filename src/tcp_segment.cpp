#include "mirage_tcp/tcp_segment.h"

namespace mirage_tcp {

namespace {

uint16_t read_u16_be(const std::vector<uint8_t>& bytes, size_t offset) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[offset]) << 8) |
        static_cast<uint16_t>(bytes[offset + 1]));
}

uint32_t read_u32_be(const std::vector<uint8_t>& bytes, size_t offset) {
    return (static_cast<uint32_t>(bytes[offset]) << 24) |
           (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<uint32_t>(bytes[offset + 3]);
}

void write_u16_be(uint16_t value, std::vector<uint8_t>* bytes, size_t offset) {
    (*bytes)[offset] = static_cast<uint8_t>((value >> 8) & 0xff);
    (*bytes)[offset + 1] = static_cast<uint8_t>(value & 0xff);
}

void write_u32_be(uint32_t value, std::vector<uint8_t>* bytes, size_t offset) {
    (*bytes)[offset] = static_cast<uint8_t>((value >> 24) & 0xff);
    (*bytes)[offset + 1] = static_cast<uint8_t>((value >> 16) & 0xff);
    (*bytes)[offset + 2] = static_cast<uint8_t>((value >> 8) & 0xff);
    (*bytes)[offset + 3] = static_cast<uint8_t>(value & 0xff);
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

int parse_tcp_segment(
    const std::vector<uint8_t>& bytes,
    TcpSegment* segment) {
    if (segment == NULL) {
        return ErrorCode::InvalidArgument;
    }

    if (bytes.size() < 20) {
        return ErrorCode::PacketTooShort;
    }

    const uint8_t data_offset_words = static_cast<uint8_t>(bytes[12] >> 4);
    if (data_offset_words < 5) {
        return ErrorCode::InvalidTcpDataOffset;
    }

    const size_t header_length = static_cast<size_t>(data_offset_words) * 4U;
    if (header_length > bytes.size()) {
        return ErrorCode::TcpHeaderTooLong;
    }

    TcpSegment parsed;
    parsed.source_port = read_u16_be(bytes, 0);
    parsed.destination_port = read_u16_be(bytes, 2);
    parsed.sequence_number = read_u32_be(bytes, 4);
    parsed.acknowledgment_number = read_u32_be(bytes, 8);
    parsed.window_size = read_u16_be(bytes, 14);

    const uint8_t flags = bytes[13];
    parsed.fin = (flags & 0x01U) != 0;
    parsed.syn = (flags & 0x02U) != 0;
    parsed.rst = (flags & 0x04U) != 0;
    parsed.ack = (flags & 0x10U) != 0;

    parsed.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(header_length), bytes.end());
    *segment = parsed;
    return ErrorCode::Ok;
}

std::vector<uint8_t> serialize_tcp_segment(const TcpSegment& segment) {
    const size_t header_length = 20;
    std::vector<uint8_t> bytes(header_length + segment.payload.size(), 0);

    write_u16_be(segment.source_port, &bytes, 0);
    write_u16_be(segment.destination_port, &bytes, 2);
    write_u32_be(segment.sequence_number, &bytes, 4);
    write_u32_be(segment.acknowledgment_number, &bytes, 8);
    bytes[12] = static_cast<uint8_t>(5U << 4);

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
    bytes[13] = flags;

    write_u16_be(segment.window_size, &bytes, 14);
    write_u16_be(0, &bytes, 16);
    write_u16_be(0, &bytes, 18);

    for (size_t i = 0; i < segment.payload.size(); ++i) {
        bytes[header_length + i] = segment.payload[i];
    }

    return bytes;
}

}  // namespace mirage_tcp

