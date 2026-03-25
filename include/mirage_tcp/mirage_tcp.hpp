#ifndef MIRAGE_TCP_MIRAGE_TCP_HPP
#define MIRAGE_TCP_MIRAGE_TCP_HPP

#include <cstddef>
#include <memory>

#include "mirage_tcp/mirage_tcp.h"
#include "mirage_tcp/connection_info.h"

namespace mirage_tcp {

using std::size_t;

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
    explicit MirageTcp(const mirage_tcp_callbacks_t & callbacks);

    MirageTcp(MirageTcp &&);

    MirageTcp & operator=(MirageTcp &&);

    ~MirageTcp();

    /**
     * @brief Accepts one inbound IP packet from the host.
     *
     * @param ip_packet Pointer to raw IP packet bytes. The caller guarantees
     *        that @p ip_packet is not null and is suitably aligned for fixed IP header access.
     * @param ip_packet_size Size of @p ip_packet in bytes.
     * @return 0 if the packet is accepted; otherwise an error code.
     */
    mirage_tcp_error_code_t handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size);

    /**
     * @brief Emits one downstream TCP payload segment on an established flow.
     *
     * @param connection_info Flow identifier.
     * @param payload Pointer to payload bytes.
     * @param payload_size Size of @p payload in bytes.
     * @return 0 if the payload is emitted; otherwise an error code.
     */
    mirage_tcp_error_code_t send_downstream_tcp_payload(
        const mirage_tcp_connection_info_t & connection_info,
        const void* payload,
        size_t payload_size);

    /**
     * @brief Starts a local close by emitting FIN+ACK for an established flow.
     *
     * @param connection_info Flow identifier.
     * @return 0 if close initiation succeeds; otherwise an error code.
     */
    mirage_tcp_error_code_t close_flow(const mirage_tcp_connection_info_t & connection_info);

private:

    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace mirage_tcp

#endif
