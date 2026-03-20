#ifndef MIRAGE_TCP_MIRAGE_TCP_H
#define MIRAGE_TCP_MIRAGE_TCP_H

#include <cstddef>
#include <cstdint>
#include <memory>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#include "mirage_tcp/ip6_head.h"
#include "mirage_tcp/typedefs.h"

namespace mirage_tcp {

using std::size_t;
using std::uint8_t;
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
    Address client_ip;
    /** @brief Server IP address. */
    Address server_ip;
    /** @brief Client TCP port. */
    uint16_t client_port;
    /** @brief Server TCP port. */
    uint16_t server_port;
    /** @brief IP version, currently 4 or 6. */
    uint8_t ip_ver;

    ConnectionInfo();
};

/**
 * @brief Strict weak ordering for using ConnectionInfo as a map key.
 */
bool operator<(const ConnectionInfo& left, const ConnectionInfo& right);

typedef void (*IpPacketGeneratedCallback)(
    void* user_data,
    const void* ip_packet,
    size_t ip_packet_size);

typedef void (*TcpHandshakeCompletedCallback)(
    void* user_data,
    const ConnectionInfo& connection_info);

typedef void (*TcpPayloadReceivedCallback)(
    void* user_data,
    const ConnectionInfo& connection_info,
    const void* payload,
    size_t payload_size);

typedef void (*TcpConnectionClosedCallback)(
    void* user_data,
    const ConnectionInfo& connection_info);

typedef void (*TcpConnectionResetCallback)(
    void* user_data,
    const ConnectionInfo& connection_info);

typedef void (*MirageTcpErrorCallback)(
    void* user_data,
    error_code_t error_code);

/**
 * @brief Host-provided callbacks used to observe MirageTCP output.
 */
struct MirageTcpCallbacks {
    void* user_data;
    /** @brief Fired whenever MirageTCP emits one downstream IPv4 packet for reinjection. */
    IpPacketGeneratedCallback on_downstream_ip_packet_generated;
    /** @brief Fired after the passive-side three-way handshake completes. */
    TcpHandshakeCompletedCallback on_tcp_handshake_completed;
    /** @brief Fired when client-to-server payload is accepted by the flow. */
    TcpPayloadReceivedCallback on_tcp_payload_received;
    /** @brief Fired when a locally terminated close completes cleanly. */
    TcpConnectionClosedCallback on_tcp_connection_closed;
    /** @brief Fired when the flow is reset or discarded. */
    TcpConnectionResetCallback on_tcp_connection_reset;
    /** @brief Fired when packet parsing or flow validation fails. */
    MirageTcpErrorCallback on_error;

    MirageTcpCallbacks();
};

/**
 * @brief Host-driven local TCP terminator for intercepted IPv4/TCP traffic.
 */
class MirageTcp {
public:
    /**
     * @brief Creates one MirageTCP instance with the supplied callbacks.
     *
     * @param callbacks Host callbacks used to consume emitted events and packets.
     */
    explicit MirageTcp(const MirageTcpCallbacks& callbacks = MirageTcpCallbacks());

    MirageTcp(MirageTcp &&);

    MirageTcp & operator=(MirageTcp &&);

    ~MirageTcp();

    /**
     * @brief Accepts one inbound IP packet from the host.
     *
     * @param ip_packet Pointer to raw IP packet bytes. The caller guarantees
     *        that @p ip_packet is not null and is aligned to alignof(Ip6Head).
     * @param ip_packet_size Size of @p ip_packet in bytes.
     * @return 0 if the packet is accepted; otherwise an error code.
     */
    error_code_t handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size);

    /**
     * @brief Emits one downstream TCP payload segment on an established flow.
     *
     * @param connection_info Flow identifier.
     * @param payload Pointer to payload bytes.
     * @param payload_size Size of @p payload in bytes.
     * @return 0 if the payload is emitted; otherwise an error code.
     */
    error_code_t send_downstream_tcp_payload(
        const ConnectionInfo& connection_info,
        const void* payload,
        size_t payload_size);

    /**
     * @brief Starts a local close by emitting FIN+ACK for an established flow.
     *
     * @param connection_info Flow identifier.
     * @return 0 if close initiation succeeds; otherwise an error code.
     */
    error_code_t close_flow(const ConnectionInfo& connection_info);

private:

    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace mirage_tcp

#endif
