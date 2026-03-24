#ifndef MIRAGE_TCP_IP4_HEAD_H
#define MIRAGE_TCP_IP4_HEAD_H

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "constants.h"

namespace mirage_tcp {

using std::uint16_t;
using std::uint32_t;
using std::uint8_t;

/**
 * @brief Fixed IPv4 header bytes in network byte order.
 */
struct Ip4Head {
    static constexpr uint8_t VERSION = 4U;

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

    uint8_t version() const {
        return version_ihl >> 4;
    }

    size_t header_length() const {
        return 4u * (version_ihl & 0x0f);
    }

    bool is_tcp() const {
        return protocol == IP_PROTOCOL_TCP;
    }
};

static_assert(sizeof(Ip4Head) == 20, "Ip4Head must match the fixed IPv4 header size");
static_assert(std::is_standard_layout<Ip4Head>::value, "Ip4Head must be standard-layout");
static_assert(std::is_trivially_copyable<Ip4Head>::value, "Ip4Head must be trivially copyable");

}  // namespace mirage_tcp

#endif
