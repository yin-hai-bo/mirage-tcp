#ifndef MIRAGE_TCP_IPV4_PACKET_H
#define MIRAGE_TCP_IPV4_PACKET_H

#include <cstddef>
#include <cstdint>

#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "mirage_tcp/defines.h"
#include "ip4_head.h"

namespace mirage_tcp {

using std::size_t;
using std::uint8_t;
using std::uint32_t;

/**
 * @brief Non-owning view of one IPv4 packet.
 */
struct Ip4PacketView {

    /** @brief IPv4 source address copied from the fixed header. */
    in_addr source_address;

    /** @brief IPv4 destination address copied from the fixed header. */
    in_addr destination_address;

    /** @brief Pointer to the payload bytes inside the original packet buffer. */
    const uint8_t* payload;

    /** @brief Payload size in bytes. */
    size_t payload_size;

    void set(
        const Ip4Head & head,
        const uint8_t * payload,
        size_t payload_size)
    {
        this->source_address.s_addr = head.source_address;
        this->destination_address.s_addr = head.destination_address;
        this->payload = payload;
        this->payload_size = payload_size;
    }
};

/**
 * @brief Parses one inbound IPv4/TCP packet into a non-owning view.
 *
 * @param packet Pointer to the raw IP packet bytes to validate as IPv4/TCP.
 *               The caller must guarantee that @p packet is not NULL.
 * @param packet_size Size of @p packet in bytes.
 * @param parsed_packet Output packet view on success.
 * @return 0 if parsing succeeds as IPv4/TCP; otherwise an error code.
 */
mirage_tcp_error_code_t parse_ipv4_tcp_packet(
    const void* packet,
    size_t packet_size,
    Ip4PacketView& parsed_packet);

/**
 * @brief Serializes an IPv4 packet and computes its header checksum.
 *
 * @param head Fixed IPv4 header bytes in network byte order.
 * @param payload Pointer to payload bytes.
 * @param payload_size Payload size in bytes.
 * @param bytes Output serialized IPv4 packet bytes on success.
 * @return 0 if serialization succeeds; otherwise an error code.
 */
mirage_tcp_error_code_t serialize_ipv4_packet(
    const Ip4Head& head,
    const void* payload,
    size_t payload_size,
    std::vector<uint8_t>* bytes);

}  // namespace mirage_tcp

#endif
