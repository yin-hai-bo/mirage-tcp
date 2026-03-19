#include "mirage_tcp/ipv4_packet.h"

namespace mirage_tcp {

namespace {

uint16_t read_u16_be(const uint8_t* bytes) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) |
        static_cast<uint16_t>(bytes[1]));
}

uint32_t read_u32_be(const uint8_t* bytes) {
    return (static_cast<uint32_t>(bytes[0]) << 24) |
           (static_cast<uint32_t>(bytes[1]) << 16) |
           (static_cast<uint32_t>(bytes[2]) << 8) |
           static_cast<uint32_t>(bytes[3]);
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

Ipv4Packet::Ipv4Packet()
    : source_address(0),
      destination_address(0),
      protocol(0),
      ttl(64) {}

bool parse_ipv4_packet(
    const void* packet,
    size_t packet_size,
    Ipv4Packet* parsed_packet,
    std::string* error_message) {
    if (packet == NULL || parsed_packet == NULL) {
        if (error_message != NULL) {
            *error_message = "ipv4 packet parse requires non-null pointers";
        }
        return false;
    }
    if (packet_size < 20) {
        if (error_message != NULL) {
            *error_message = "ipv4 packet must be at least 20 bytes";
        }
        return false;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(packet);
    const uint8_t version = static_cast<uint8_t>(bytes[0] >> 4);
    const uint8_t ihl_words = static_cast<uint8_t>(bytes[0] & 0x0fU);
    if (version != 4) {
        if (error_message != NULL) {
            *error_message = "only IPv4 packets are supported";
        }
        return false;
    }
    if (ihl_words < 5) {
        if (error_message != NULL) {
            *error_message = "ipv4 header length must be at least 5 words";
        }
        return false;
    }

    const size_t header_size = static_cast<size_t>(ihl_words) * 4U;
    const uint16_t total_length = read_u16_be(bytes + 2);
    if (total_length < header_size || total_length > packet_size) {
        if (error_message != NULL) {
            *error_message = "ipv4 total length is invalid";
        }
        return false;
    }

    const uint16_t flags_and_fragment = read_u16_be(bytes + 6);
    if ((flags_and_fragment & 0x1fffU) != 0U) {
        if (error_message != NULL) {
            *error_message = "fragmented ipv4 packets are not supported";
        }
        return false;
    }

    Ipv4Packet result;
    result.protocol = bytes[9];
    result.ttl = bytes[8];
    result.source_address = read_u32_be(bytes + 12);
    result.destination_address = read_u32_be(bytes + 16);
    result.payload.assign(
        bytes + static_cast<std::ptrdiff_t>(header_size),
        bytes + static_cast<std::ptrdiff_t>(total_length));
    *parsed_packet = result;

    if (error_message != NULL) {
        error_message->clear();
    }
    return true;
}

std::vector<uint8_t> serialize_ipv4_packet(
    const Ipv4Packet& packet,
    std::string* error_message) {
    const size_t header_size = 20;
    const size_t total_size = header_size + packet.payload.size();
    if (total_size > 0xffffU) {
        if (error_message != NULL) {
            *error_message = "ipv4 packet too large";
        }
        return std::vector<uint8_t>();
    }

    std::vector<uint8_t> bytes(total_size, 0);
    bytes[0] = 0x45;
    write_u16_be(static_cast<uint16_t>(total_size), &bytes[2]);
    bytes[8] = packet.ttl;
    bytes[9] = packet.protocol;
    write_u32_be(packet.source_address, &bytes[12]);
    write_u32_be(packet.destination_address, &bytes[16]);
    write_u16_be(internet_checksum(&bytes[0], header_size), &bytes[10]);

    for (size_t i = 0; i < packet.payload.size(); ++i) {
        bytes[header_size + i] = packet.payload[i];
    }

    if (error_message != NULL) {
        error_message->clear();
    }
    return bytes;
}

}  // namespace mirage_tcp
