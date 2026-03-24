#ifndef MIRAGE_TCP_IP6_HEAD_H
#define MIRAGE_TCP_IP6_HEAD_H

#include <cstdint>
#include <type_traits>

namespace mirage_tcp {

using std::uint16_t;
using std::uint32_t;
using std::uint8_t;

/**
 * @brief Fixed IPv6 header bytes in network byte order.
 */
struct Ip6Head {
    static constexpr uint8_t VERSION = 6U;

    uint32_t ver_tc_flow_label;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    uint8_t source_address[16];
    uint8_t destination_address[16];
};

static_assert(sizeof(Ip6Head) == 40, "Ip6Head must match the fixed IPv6 header size");
static_assert(std::is_standard_layout<Ip6Head>::value, "Ip6Head must be standard-layout");
static_assert(std::is_trivially_copyable<Ip6Head>::value, "Ip6Head must be trivially copyable");

}  // namespace mirage_tcp

#endif
