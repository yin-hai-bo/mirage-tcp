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

enum Ipv4PacketErrorCode {
    kIpv4PacketOk = 0,
    kIpv4PacketNullPointer = 1,
    kIpv4PacketTooShort = 2,
    kIpv4PacketUnsupportedVersion = 3,
    kIpv4PacketInvalidHeaderLength = 4,
    kIpv4PacketInvalidTotalLength = 5,
    kIpv4PacketFragmentUnsupported = 6,
    kIpv4PacketSerializeTooLarge = 7
};

/**
 * @brief Parses one inbound IPv4 packet.
 *
 * @param packet Pointer to the raw IPv4 packet bytes.
 * @param packet_size Size of @p packet in bytes.
 * @param parsed_packet Output packet structure on success.
 * @return 0 if parsing succeeds; otherwise an error code.
 */
int parse_ipv4_packet(
    const void* packet,
    size_t packet_size,
    Ipv4Packet* parsed_packet);

/**
 * @brief Serializes an IPv4 packet and computes its header checksum.
 *
 * @param packet Parsed packet fields to serialize.
 * @param bytes Output serialized IPv4 packet bytes on success.
 * @return 0 if serialization succeeds; otherwise an error code.
 */
int serialize_ipv4_packet(
    const Ipv4Packet& packet,
    std::vector<uint8_t>* bytes);

}  // namespace mirage_tcp

#endif
