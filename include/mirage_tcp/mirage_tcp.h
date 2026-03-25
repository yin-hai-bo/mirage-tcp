#ifndef MIRAGE_TCP_MIRAGE_TCP_H
#define MIRAGE_TCP_MIRAGE_TCP_H

#include <stddef.h>
#include "mirage_tcp/defines.h"
#include "mirage_tcp/connection_info.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Fired whenever MirageTCP emits one downstream IPv4 packet.
 *
 * @param user_data Host-provided opaque context pointer.
 * @param ip_packet Pointer to the generated packet bytes.
 * @param ip_packet_size Size of @p ip_packet in bytes.
 */
typedef void (*mirage_tcp_ip_packet_generated_callback_t)(
    void * user_data,
    const void * ip_packet,
    size_t ip_packet_size);

/**
 * @brief Fired after the passive-side three-way handshake completes.
 *
 * @param user_data Host-provided opaque context pointer.
 * @param connection_info Established flow identifier.
 */
typedef void (*mirage_tcp_handshake_completed_callback_t)(
    void * user_data,
    const mirage_tcp_connection_info_t * connection_info);

/**
 * @brief Fired when client-to-server payload is accepted by the flow.
 *
 * @param user_data Host-provided opaque context pointer.
 * @param connection_info Flow identifier.
 * @param payload Pointer to accepted payload bytes.
 * @param payload_size Size of @p payload in bytes.
 */
typedef void (*mirage_tcp_payload_received_callback_t)(
    void * user_data,
    const mirage_tcp_connection_info_t * connection_info,
    const void * payload,
    size_t payload_size);

/**
 * @brief Fired when a locally terminated close completes cleanly.
 *
 * @param user_data Host-provided opaque context pointer.
 * @param connection_info Closed flow identifier.
 */
typedef void (*mirage_tcp_connection_closed_callback_t)(
    void * user_data,
    const mirage_tcp_connection_info_t * connection_info);

/**
 * @brief Fired when the flow is reset or discarded.
 *
 * @param user_data Host-provided opaque context pointer.
 * @param connection_info Affected flow identifier.
 */
typedef void (*mirage_tcp_connection_reset_callback_t)(
    void * user_data,
    const mirage_tcp_connection_info_t * connection_info);

/**
 * @brief Host-provided callbacks used to observe MirageTCP output.
 */
typedef struct {

    void * user_data;

    /** @brief Fired whenever MirageTCP emits one downstream IPv4 packet for reinjection. */
    mirage_tcp_ip_packet_generated_callback_t on_downstream_ip_packet_generated;

    /** @brief Fired after the passive-side three-way handshake completes. */
    mirage_tcp_handshake_completed_callback_t on_tcp_handshake_completed;

    /** @brief Fired when client-to-server payload is accepted by the flow. */
    mirage_tcp_payload_received_callback_t on_tcp_payload_received;

    /** @brief Fired when a locally terminated close completes cleanly. */
    mirage_tcp_connection_closed_callback_t on_tcp_connection_closed;

    /** @brief Fired when the flow is reset or discarded. */
    mirage_tcp_connection_reset_callback_t on_tcp_connection_reset;

} mirage_tcp_callbacks_t;

struct mirage_tcp_object_s;

typedef mirage_tcp_object_s * mirage_tcp_object;

/**
 * @brief Creates one MirageTCP instance for the supplied callbacks.
 *
 * @param callbacks Callback table. Must not be NULL. Individual callback
 *        fields may be NULL when the host does not need that event.
 * @param result Output handle. Must not be NULL. Receives NULL on failure.
 * @return `MTE_Ok` on success; otherwise an error code such as
 *         `MTE_InvalidArgument` or `MTE_OutOfMemory`.
 */
mirage_tcp_error_code_t mirage_tcp_create(mirage_tcp_callbacks_t const * callbacks, mirage_tcp_object * result);

/**
 * @brief Destroys one MirageTCP instance previously returned by
 *        `mirage_tcp_create()`.
 *
 * @param instance MirageTCP handle. NULL is allowed and is ignored.
 */
void mirage_tcp_destroy(mirage_tcp_object);

/**
 * @brief Accepts one inbound IP packet from the host.
 *
 * @param instance MirageTCP handle returned by `mirage_tcp_create()`.
 * @param ip_packet Pointer to one raw IP packet.
 * @param ip_packet_size Size of @p ip_packet in bytes.
 * @return `MTE_Ok` on success; otherwise an error code.
 */
mirage_tcp_error_code_t mirage_tcp_handle_incoming_ip_packet(mirage_tcp_object, const void * ip_packet, size_t ip_packet_size);

/**
 * @brief Emits one downstream TCP payload segment on an established flow.
 *
 * @param instance MirageTCP handle returned by `mirage_tcp_create()`.
 * @param connection_info Flow identifier. Must not be NULL.
 * @param payload Pointer to payload bytes.
 * @param payload_size Size of @p payload in bytes.
 * @return `MTE_Ok` on success; otherwise an error code.
 */
mirage_tcp_error_code_t mirage_tcp_send_downstream_tcp_payload(
    mirage_tcp_object,
    const mirage_tcp_connection_info_t * connection_info,
    const void * payload,
    size_t payload_size);

/**
 * @brief Starts a local close by emitting FIN+ACK for an established flow.
 *
 * @param instance MirageTCP handle returned by `mirage_tcp_create()`.
 * @param connection_info Flow identifier. Must not be NULL.
 * @return `MTE_Ok` on success; otherwise an error code.
 */
mirage_tcp_error_code_t mirage_tcp_close_flow(mirage_tcp_object, const mirage_tcp_connection_info_t * connection_info);

#ifdef __cplusplus
}
#endif

#endif
