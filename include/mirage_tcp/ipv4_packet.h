#ifndef MIRAGE_TCP_IPV4_PACKET_H
#define MIRAGE_TCP_IPV4_PACKET_H

#include <cstddef>
#include <cstdint>

#include <vector>

#include "mirage_tcp/typedefs.h"
#include "mirage_tcp/error_code.h"
#include "mirage_tcp/ip4_head.h"

namespace mirage_tcp {

using std::size_t;
using std::uint8_t;
using std::uint32_t;

/**
 * @brief Non-owning view of one IPv4 packet.
 */
struct Ip4PacketView {
    /** @brief Pointer to the fixed IPv4 header inside the original packet buffer. */
    const Ip4Head* head;
    /** @brief Pointer to the payload bytes inside the original packet buffer. */
    const uint8_t* payload;
    /** @brief Payload size in bytes. */
    size_t payload_size;
};

/**
 * @brief Serializes an IPv4 packet and computes its header checksum.
 *
 * @param head Fixed IPv4 header bytes in network byte order.
 * @param payload Pointer to payload bytes.
 * @param payload_size Payload size in bytes.
 * @param bytes Output serialized IPv4 packet bytes on success.
 * @return 0 if serialization succeeds; otherwise an error code.
 */
error_code_t serialize_ipv4_packet(
    const Ip4Head& head,
    const void* payload,
    size_t payload_size,
    std::vector<uint8_t>* bytes);

}  // namespace mirage_tcp

#endif

