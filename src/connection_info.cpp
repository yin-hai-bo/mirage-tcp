#include "mirage_tcp/connection_info.h"

#include <cstring>

namespace mirage_tcp {

namespace {

ConnectionInfo::Address make_ipv4_address_storage(const in_addr& address) {
    ConnectionInfo::Address value = {};
    value.ipv4 = address;
    return value;
}

ConnectionInfo::Address make_ipv6_address_storage(const in6_addr& address) {
    ConnectionInfo::Address value = {};
    value.ipv6 = address;
    return value;
}

}  // namespace

ConnectionInfo::ConnectionInfo(
    const in_addr& client_ipv4,
    const in_addr& server_ipv4,
    uint16_t client_port_value,
    uint16_t server_port_value)
    : client_ip(make_ipv4_address_storage(client_ipv4)),
      server_ip(make_ipv4_address_storage(server_ipv4)),
      client_port(client_port_value),
      server_port(server_port_value),
      ip_ver(4) {}

ConnectionInfo::ConnectionInfo(
    const in6_addr& client_ipv6,
    const in6_addr& server_ipv6,
    uint16_t client_port_value,
    uint16_t server_port_value)
    : client_ip(make_ipv6_address_storage(client_ipv6)),
      server_ip(make_ipv6_address_storage(server_ipv6)),
      client_port(client_port_value),
      server_port(server_port_value),
      ip_ver(6) {}

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
    return ConnectionInfoEqual()(left, right);
}

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
