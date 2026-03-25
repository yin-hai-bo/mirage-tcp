#include "connection_info.hpp"

#include <cstring>
#include <type_traits>

using mirage_tcp::ConnectionInfo;

static_assert(std::is_standard_layout<mirage_tcp_address_t>::value, "mirage_tcp_address_t must be standard-layout");
static_assert(std::is_trivially_copyable<mirage_tcp_address_t>::value, "mirage_tcp_address_t must be trivially copyable");
static_assert(std::is_standard_layout<ConnectionInfo>::value, "ConnectionInfo must be standard-layout");
static_assert(std::is_trivially_copyable<ConnectionInfo>::value, "ConnectionInfo must be trivially copyable");

extern "C" {

static void set_connection_info(
    uint8_t ip_ver,
    uint16_t client_port,
    uint16_t server_port,
    ConnectionInfo * target)
{
    if (target == nullptr) {
        return;
    }
    std::memset(target, 0, sizeof(*target));
    target->client_port = client_port;
    target->server_port = server_port;
    target->ip_ver = ip_ver;
}

void mirage_tcp_set_connection_info_v4(
    const struct in_addr * client_ipv4,
    const struct in_addr * server_ipv4,
    uint16_t client_port,
    uint16_t server_port,
    ConnectionInfo * target)
{
    if (client_ipv4 == nullptr || server_ipv4 == nullptr || target == nullptr) {
        return;
    }
    set_connection_info(4, client_port, server_port, target);
    target->client_ip.ipv4.s_addr = client_ipv4->s_addr;
    target->server_ip.ipv4.s_addr = server_ipv4->s_addr;
}

void mirage_tcp_set_connection_info_v6(
    const struct in6_addr * client_ipv6,
    const struct in6_addr * server_ipv6,
    uint16_t client_port,
    uint16_t server_port,
    ConnectionInfo * target)
{
    if (client_ipv6 == nullptr || server_ipv6 == nullptr || target == nullptr) {
        return;
    }
    set_connection_info(6, client_port, server_port, target);
    std::memcpy(&target->client_ip.ipv6, client_ipv6, sizeof(in6_addr));
    std::memcpy(&target->server_ip.ipv6, server_ipv6, sizeof(in6_addr));
}

} // extern "C"

bool operator<(const ConnectionInfo& left, const ConnectionInfo& right) {
    if (left.ip_ver != right.ip_ver) {
        return left.ip_ver < right.ip_ver;
    }

    if (left.client_port != right.client_port) {
        return left.client_port < right.client_port;
    }

    if (left.server_port != right.server_port) {
        return left.server_port < right.server_port;
    }

    if (left.ip_ver == 4) {
        if (left.client_ip.ipv4.s_addr != right.client_ip.ipv4.s_addr) {
            return left.client_ip.ipv4.s_addr < right.client_ip.ipv4.s_addr;
        }

        return left.server_ip.ipv4.s_addr < right.server_ip.ipv4.s_addr;
    }

    const int client_compare =
        std::memcmp(&left.client_ip.ipv6, &right.client_ip.ipv6, sizeof(left.client_ip.ipv6));
    if (client_compare != 0) {
        return client_compare < 0;
    }

    return std::memcmp(&left.server_ip.ipv6, &right.server_ip.ipv6, sizeof(left.server_ip.ipv6)) < 0;
}

bool operator==(const ConnectionInfo& left, const ConnectionInfo& right) {
    return mirage_tcp::ConnectionInfoEqual()(left, right);
}

namespace mirage_tcp {

size_t ConnectionInfoHash::operator()(const ConnectionInfo& connection_info) const {
    const uint32_t ports =
        (static_cast<uint32_t>(connection_info.client_port) << 16) |
        static_cast<uint32_t>(connection_info.server_port);
    uint32_t hash = ports ^ static_cast<uint32_t>(connection_info.ip_ver);

    if (connection_info.ip_ver == 4) {
        hash ^= connection_info.client_ip.ipv4.s_addr;
        hash ^= connection_info.server_ip.ipv4.s_addr;
    } else {
        // We normalize into aligned uint32_t words because some supported
        // platforms expose in6_addr with insufficient alignment for direct
        // uint32_t pointer access.
        uint32_t words[8] = {};
        std::memcpy(&words[0], &connection_info.client_ip.ipv6, sizeof(connection_info.client_ip.ipv6));
        std::memcpy(&words[4], &connection_info.server_ip.ipv6, sizeof(connection_info.server_ip.ipv6));
        for (size_t i = 0; i < 8; ++i) {
            hash ^= words[i];
        }
    }
    return static_cast<size_t>(hash);
}

bool ConnectionInfoEqual::operator()(const ConnectionInfo& left, const ConnectionInfo& right) const {
    if (left.ip_ver != right.ip_ver) {
        return false;
    }

    if (left.client_port != right.client_port) {
        return false;
    }

    if (left.server_port != right.server_port) {
        return false;
    }

    if (left.ip_ver == 4) {
        return left.client_ip.ipv4.s_addr == right.client_ip.ipv4.s_addr &&
               left.server_ip.ipv4.s_addr == right.server_ip.ipv4.s_addr;
    }

    return std::memcmp(&left.client_ip.ipv6, &right.client_ip.ipv6, sizeof(left.client_ip.ipv6)) == 0 &&
           std::memcmp(&left.server_ip.ipv6, &right.server_ip.ipv6, sizeof(left.server_ip.ipv6)) == 0;
}

}  // namespace mirage_tcp
