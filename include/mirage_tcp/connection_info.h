#ifndef MIRAGE_TCP_CONNECTION_INFO_H
#define MIRAGE_TCP_CONNECTION_INFO_H

#include <cstddef>
#include <cstdint>
#include <type_traits>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

namespace mirage_tcp {

using std::size_t;
using std::uint16_t;
using ::in_addr;
using ::in6_addr;

/**
 * @brief Identifies one TCP flow from the host-facing perspective.
 */
struct ConnectionInfo {
    union Address {
        in_addr ipv4;
        in6_addr ipv6;
    };

    /** @brief Client IP address. */
    const Address client_ip;
    /** @brief Server IP address. */
    const Address server_ip;
    /** @brief Client TCP port. */
    const uint16_t client_port;
    /** @brief Server TCP port. */
    const uint16_t server_port;
    /** @brief IP version, currently 4 or 6. */
    const uint8_t ip_ver;

    ConnectionInfo(
        const in_addr& client_ipv4,
        const in_addr& server_ipv4,
        uint16_t client_port,
        uint16_t server_port);

    ConnectionInfo(
        const in6_addr& client_ipv6,
        const in6_addr& server_ipv6,
        uint16_t client_port,
        uint16_t server_port);
};

static_assert(std::is_standard_layout<ConnectionInfo::Address>::value, "ConnectionInfo::Address must be standard-layout");
static_assert(std::is_trivially_copyable<ConnectionInfo::Address>::value, "ConnectionInfo::Address must be trivially copyable");
static_assert(std::is_standard_layout<ConnectionInfo>::value, "ConnectionInfo must be standard-layout");
static_assert(std::is_trivially_copyable<ConnectionInfo>::value, "ConnectionInfo must be trivially copyable");

/**
 * @brief Strict weak ordering for using ConnectionInfo as a map key.
 */
bool operator<(const ConnectionInfo& left, const ConnectionInfo& right);
bool operator==(const ConnectionInfo& left, const ConnectionInfo& right);

struct ConnectionInfoHash {
    size_t operator()(const ConnectionInfo& connection_info) const;
};

struct ConnectionInfoEqual {
    bool operator()(const ConnectionInfo& left, const ConnectionInfo& right) const;
};

}  // namespace mirage_tcp

#endif
