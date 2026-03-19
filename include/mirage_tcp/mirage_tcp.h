#ifndef MIRAGE_TCP_MIRAGE_TCP_H
#define MIRAGE_TCP_MIRAGE_TCP_H

#include <cstddef>
#include <cstdint>

#include <map>
#include <string>

namespace mirage_tcp {

using std::size_t;
using std::uint8_t;
using std::uint16_t;
using std::uint32_t;

/**
 * @brief Identifies one TCP flow from the host-facing perspective.
 */
struct FiveTuple {
    /** @brief Client IPv4 address in network byte order. */
    uint32_t client_ip;
    /** @brief Server IPv4 address in network byte order. */
    uint32_t server_ip;
    /** @brief Client TCP port. */
    uint16_t client_port;
    /** @brief Server TCP port. */
    uint16_t server_port;
    /** @brief IP protocol number, currently expected to be TCP. */
    uint8_t protocol;

    FiveTuple();
};

/**
 * @brief Strict weak ordering for using FiveTuple as a map key.
 */
bool operator<(const FiveTuple& left, const FiveTuple& right);

typedef void (*IpPacketGeneratedCallback)(
    void* user_data,
    const void* ip_packet,
    size_t ip_packet_size);

typedef void (*TcpHandshakeCompletedCallback)(
    void* user_data,
    const FiveTuple& five_tuple);

typedef void (*TcpPayloadReceivedCallback)(
    void* user_data,
    const FiveTuple& five_tuple,
    const void* payload,
    size_t payload_size);

typedef void (*TcpConnectionClosedCallback)(
    void* user_data,
    const FiveTuple& five_tuple);

typedef void (*TcpConnectionResetCallback)(
    void* user_data,
    const FiveTuple& five_tuple);

typedef void (*MirageTcpErrorCallback)(
    void* user_data,
    const char* message);

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

    /**
     * @brief Accepts one inbound IPv4 packet from the host.
     *
     * @param ip_packet Pointer to raw IPv4 packet bytes.
     * @param ip_packet_size Size of @p ip_packet in bytes.
     * @return true if the packet is accepted; otherwise false.
     */
    bool handle_incoming_ip_packet(const void* ip_packet, size_t ip_packet_size);
    /**
     * @brief Emits one downstream TCP payload segment on an established flow.
     *
     * @param five_tuple Flow identifier.
     * @param payload Pointer to payload bytes.
     * @param payload_size Size of @p payload in bytes.
     * @return true if the payload is emitted; otherwise false.
     */
    bool send_downstream_tcp_payload(const FiveTuple& five_tuple, const void* payload, size_t payload_size);
    /**
     * @brief Starts a local close by emitting FIN+ACK for an established flow.
     *
     * @param five_tuple Flow identifier.
     * @return true if close initiation succeeds; otherwise false.
     */
    bool close_flow(const FiveTuple& five_tuple);

private:
    enum class FlowState {
        kSynReceived,
        kEstablished,
        kLastAck
    };

    struct Flow {
        FiveTuple five_tuple;
        FlowState state;
        uint32_t client_next_sequence;
        uint32_t server_initial_sequence;
        uint32_t server_next_sequence;
    };

    void emit_error(const std::string& message) const;
    void emit_downstream_ip_packet(const void* ip_packet, size_t ip_packet_size) const;
    void emit_reset(const FiveTuple& five_tuple) const;
    bool handle_syn(const FiveTuple& five_tuple, uint32_t client_sequence);
    bool handle_established_packet(
        Flow* flow,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        bool ack_flag,
        bool fin_flag,
        bool rst_flag,
        const void* payload,
        size_t payload_size);
    bool handle_last_ack_packet(
        Flow* flow,
        uint32_t acknowledgment_number,
        bool ack_flag);
    bool emit_reset_for_unhandled_packet(
        const FiveTuple& five_tuple,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        bool ack_flag,
        bool syn_flag,
        bool fin_flag,
        size_t payload_size);
    bool fail_flow(
        const FiveTuple& five_tuple,
        const std::string& message,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        bool ack_flag,
        bool syn_flag,
        bool fin_flag,
        size_t payload_size);
    bool emit_tcp_response(
        const FiveTuple& five_tuple,
        uint32_t sequence_number,
        uint32_t acknowledgment_number,
        bool syn_flag,
        bool ack_flag,
        bool fin_flag,
        bool rst_flag,
        const void* payload,
        size_t payload_size);

    MirageTcpCallbacks callbacks_;
    std::map<FiveTuple, Flow> flows_;
};

}  // namespace mirage_tcp

#endif
