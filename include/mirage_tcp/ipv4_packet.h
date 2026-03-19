#ifndef MIRAGE_TCP_IPV4_PACKET_H
#define MIRAGE_TCP_IPV4_PACKET_H

#include <cstddef>
#include <cstdint>

#include <string>
#include <vector>

namespace mirage_tcp {

using std::size_t;
using std::uint8_t;
using std::uint32_t;

/**
 * @brief Parsed IPv4 packet without options.
 */
struct Ipv4Packet {
    /** @brief Source IPv4 address in network byte order. */
    uint32_t source_address;
    /** @brief Destination IPv4 address in network byte order. */
    uint32_t destination_address;
    /** @brief IP protocol number carried by this packet. */
    uint8_t protocol;
    /** @brief Time-to-live value copied from the IPv4 header. */
    uint8_t ttl;
    /** @brief Payload bytes after the IPv4 header. */
    std::vector<uint8_t> payload;

    Ipv4Packet();
};

/**
 * @brief Parses one inbound IPv4 packet.
 *
 * @param packet Pointer to the raw IPv4 packet bytes.
 * @param packet_size Size of @p packet in bytes.
 * @param parsed_packet Output packet structure on success.
 * @param error_message Optional output error text on failure.
 * @return true if parsing succeeds; otherwise false.
 */
bool parse_ipv4_packet(
    const void* packet,
    size_t packet_size,
    Ipv4Packet* parsed_packet,
    std::string* error_message);

/**
 * @brief Serializes an IPv4 packet and computes its header checksum.
 *
 * @param packet Parsed packet fields to serialize.
 * @param error_message Optional output error text on failure.
 * @return Serialized IPv4 packet bytes, or an empty vector on failure.
 */
std::vector<uint8_t> serialize_ipv4_packet(
    const Ipv4Packet& packet,
    std::string* error_message);

}  // namespace mirage_tcp

#endif
