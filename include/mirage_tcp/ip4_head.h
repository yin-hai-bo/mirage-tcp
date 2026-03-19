#ifndef MIRAGE_TCP_IP4_HEAD_H
#define MIRAGE_TCP_IP4_HEAD_H

#include <cstdint>

namespace mirage_tcp {

using std::uint16_t;
using std::uint32_t;
using std::uint8_t;

/**
 * @brief Fixed IPv4 header bytes in network byte order.
 */
struct Ip4Head {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source_address;
    uint32_t destination_address;
};

static_assert(sizeof(Ip4Head) == 20, "Ip4Head must match the fixed IPv4 header size");

}  // namespace mirage_tcp

#endif
