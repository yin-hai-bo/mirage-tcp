#ifndef MIRAGE_TCP_CONNECTION_INFO_H
#define MIRAGE_TCP_CONNECTION_INFO_H

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    struct in_addr ipv4;
    struct in6_addr ipv6;
} mirage_tcp_address_t;

/**
 * @brief Identifies one TCP flow from the host-facing perspective.
 */
typedef struct {
    /** @brief Client IP address. */
    mirage_tcp_address_t client_ip;

    /** @brief Server IP address. */
    mirage_tcp_address_t server_ip;

    /** @brief Client TCP port. */
    uint16_t client_port;

    /** @brief Server TCP port. */
    uint16_t server_port;

    /** @brief IP version, currently 4 or 6. */
    uint8_t ip_ver;

} mirage_tcp_connection_info_t;

/**
 * @brief Fills one IPv4 connection descriptor.
 *
 * @param client_ipv4 Client IPv4 address.
 * @param server_ipv4 Server IPv4 address.
 * @param client_port Client TCP port.
 * @param server_port Server TCP port.
 * @param target Output structure to initialize.
 */
void mirage_tcp_set_connection_info_v4(
    const struct in_addr * client_ipv4,
    const struct in_addr * server_ipv4,
    uint16_t client_port,
    uint16_t server_port,
    mirage_tcp_connection_info_t * target);

/**
 * @brief Fills one IPv6 connection descriptor.
 *
 * @param client_ipv6 Client IPv6 address.
 * @param server_ipv6 Server IPv6 address.
 * @param client_port Client TCP port.
 * @param server_port Server TCP port.
 * @param target Output structure to initialize.
 */
void mirage_tcp_set_connection_info_v6(
    const struct in6_addr * client_ipv6,
    const struct in6_addr * server_ipv6,
    uint16_t client_port,
    uint16_t server_port,
    mirage_tcp_connection_info_t * target);

#ifdef __cplusplus
}
#endif

#endif
