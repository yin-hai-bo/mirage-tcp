#include "mirage_tcp/ipv4_packet.h"

#include <cassert>
#include <cstring>

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

void write_u32_be(uint32_t value, uint8_t* bytes) {
    bytes[0] = static_cast<uint8_t>((value >> 24) & 0xff);
    bytes[1] = static_cast<uint8_t>((value >> 16) & 0xff);
    bytes[2] = static_cast<uint8_t>((value >> 8) & 0xff);
    bytes[3] = static_cast<uint8_t>(value & 0xff);
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

}  // namespace

error_code_t parse_ipv4_tcp_packet(
    const void* packet,
    size_t packet_size,
    Ip4PacketView& result)
{
    if (packet_size < sizeof(Ip4Head)) {
        return ErrorCode::PacketTooShort;
    }

    Ip4Head head;
    std::memcpy(&head, packet, sizeof(head));

    if (head.version() != Ip4Head::VERSION) {
        return ErrorCode::UnsupportedIpVersion;
    }

    if (!head.is_tcp()) {
        return ErrorCode::IsNotTcp;
    }

    const size_t header_size = head.header_length();
    if (header_size < sizeof(Ip4Head)) {
        return ErrorCode::InvalidIpv4HeaderLength;
    }

    const uint16_t total_length = ntohs(head.total_length);
    if (total_length < header_size || total_length > packet_size) {
        return ErrorCode::InvalidIpv4TotalLength;
    }

    const uint16_t flags_and_fragment = ntohs(head.flags_fragment_offset);
    if ((flags_and_fragment & 0x1fffU) != 0U) {
        return ErrorCode::Ipv4FragmentUnsupported;
    }

    result.set(
        head,
        static_cast<const uint8_t*>(packet) + header_size,
        total_length - header_size);
    return ErrorCode::Ok;
}

error_code_t serialize_ipv4_packet(
    const Ip4Head& head,
    const void* payload,
    size_t payload_size,
    std::vector<uint8_t>* bytes) {
    if (bytes == NULL) {
        return ErrorCode::InvalidArgument;
    }

    const size_t header_size = sizeof(Ip4Head);
    const size_t total_size = header_size + payload_size;
    if (total_size > 0xffffU) {
        return ErrorCode::PacketTooLarge;
    }

    std::vector<uint8_t> serialized_bytes(total_size, 0);
    std::memcpy(&serialized_bytes[0], &head, sizeof(head));
    write_u16_be(static_cast<uint16_t>(total_size), &serialized_bytes[2]);
    write_u16_be(0, &serialized_bytes[10]);
    write_u16_be(internet_checksum(&serialized_bytes[0], header_size), &serialized_bytes[10]);

    if (payload != NULL && payload_size > 0) {
        const uint8_t* payload_bytes = static_cast<const uint8_t*>(payload);
        for (size_t i = 0; i < payload_size; ++i) {
            serialized_bytes[header_size + i] = payload_bytes[i];
        }
    }

    *bytes = serialized_bytes;
    return ErrorCode::Ok;
}

}  // namespace mirage_tcp
