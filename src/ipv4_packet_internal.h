#ifndef MIRAGE_TCP_IPV4_PACKET_INTERNAL_H
#define MIRAGE_TCP_IPV4_PACKET_INTERNAL_H

#include "mirage_tcp/ipv4_packet.h"

namespace mirage_tcp {

/**
 * @brief Parses one inbound IPv4 packet into a non-owning view.
 *
 * @param packet Pointer to the raw IP packet bytes to validate as IPv4.
 *               The caller must guarantee that @p packet is not NULL.
 * @param packet_size Size of @p packet in bytes.
 * @param parsed_packet Output packet view on success.
 * @return 0 if parsing succeeds as IPv4; otherwise an error code.
 */
error_code_t parse_ipv4_packet(
    const void* packet,
    size_t packet_size,
    Ip4PacketView& parsed_packet);

}  // namespace mirage_tcp

#endif
