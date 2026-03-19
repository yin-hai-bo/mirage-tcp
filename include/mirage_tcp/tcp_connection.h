#ifndef MIRAGE_TCP_TCP_CONNECTION_H
#define MIRAGE_TCP_TCP_CONNECTION_H

#include <cstddef>
#include <cstdint>

#include <vector>

#include "mirage_tcp/tcp_segment.h"

namespace mirage_tcp {

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;

/**
 * @brief Simplified TCP connection state machine.
 */
enum class TcpState {
    kClosed,
    kSynSent,
    kEstablished,
    kFinWait1,
    kFinWait2,
    kClosing,
    kTimeWait
};

/**
 * @brief Types of events emitted by TcpConnection.
 */
enum class ConnectionEventType {
    kStateChanged,
    kDataReceived,
    kConnectionClosed,
    kError
};

enum TcpConnectionErrorCode {
    kTcpConnectionOk = 0,
    kTcpConnectionConnectInvalidState = 1,
    kTcpConnectionWriteInvalidState = 2,
    kTcpConnectionWriteAfterClose = 3,
    kTcpConnectionCloseInvalidState = 4,
    kTcpConnectionPeerMismatch = 5,
    kTcpConnectionClosedState = 6,
    kTcpConnectionUnhandledState = 7,
    kTcpConnectionSynAckExpected = 8,
    kTcpConnectionAckUnexpected = 9,
    kTcpConnectionPayloadOutOfOrder = 10,
    kTcpConnectionFinSequenceUnexpected = 11,
    kTcpConnectionSegmentParseFailed = 12,
    kTcpConnectionClosedByReset = 13,
    kTcpConnectionClosedByPeerFin = 14,
    kTcpConnectionTimeWaitExpired = 15
};

/**
 * @brief One serialized outbound TCP segment with its parsed fields.
 */
struct OutgoingSegment {
    TcpSegment segment;
    std::vector<uint8_t> bytes;
};

/**
 * @brief One state or data event emitted by TcpConnection.
 */
struct ConnectionEvent {
    ConnectionEventType type;
    TcpState state;
    std::vector<uint8_t> data;
    int event_code;
};

/**
 * @brief Host-driven TCP connection state machine for one peer.
 */
class TcpConnection {
public:
    /**
     * @brief Creates one TCP connection state machine.
     *
     * @param local_port Local TCP port to advertise in outbound segments.
     * @param initial_sequence_number Initial local sequence number.
     * @param advertised_window Receive window advertised to the peer.
     */
    explicit TcpConnection(
        uint16_t local_port,
        uint32_t initial_sequence_number = 1000,
        uint16_t advertised_window = 4096);

    /**
     * @brief Starts an active open by emitting a SYN.
     *
     * @param remote_port Peer TCP port.
     * @return 0 if the connect attempt is started; otherwise an error code.
     */
    int connect(uint16_t remote_port);

    /**
     * @brief Queues payload for transmission on an established connection.
     *
     * @param data Payload bytes to send.
     * @return 0 if the payload is accepted; otherwise an error code.
     */
    int write(const std::vector<uint8_t>& data);

    /**
     * @brief Starts a local close when allowed by the current state.
     *
     * @return 0 if close processing is started; otherwise an error code.
     */
    int close();

    /**
     * @brief Pushes one parsed inbound TCP segment into the state machine.
     *
     * @param segment Parsed TCP segment from the peer.
     * @return 0 if the segment is accepted; otherwise an error code.
     */
    int push_incoming_segment(const TcpSegment& segment);

    /**
     * @brief Parses and pushes one inbound TCP segment.
     *
     * @param bytes Raw TCP segment bytes.
     * @return 0 if the bytes are accepted; otherwise an error code.
     */
    int push_incoming_bytes(const std::vector<uint8_t>& bytes);

    /**
     * @brief Advances timer-driven state such as TIME-WAIT expiration.
     *
     * @param elapsed_ms Elapsed time in milliseconds since the last tick.
     */
    void tick(uint32_t elapsed_ms);

    /**
     * @brief Returns and clears queued outbound segments.
     *
     * @return Outbound segments queued since the last drain.
     */
    std::vector<OutgoingSegment> drain_outgoing();

    /**
     * @brief Returns and clears queued connection events.
     *
     * @return Events queued since the last drain.
     */
    std::vector<ConnectionEvent> drain_events();

    /** @brief Returns the current TCP state. */
    TcpState state() const;

    /** @brief Returns the configured local TCP port. */
    uint16_t local_port() const;

    /** @brief Returns the configured remote TCP port. */
    uint16_t remote_port() const;

    /** @brief Returns whether a remote TCP port has been configured. */
    bool has_remote_port() const;

private:
    struct PendingTransmission {
        uint32_t sequence_begin;
        uint32_t sequence_end;
        bool fin;
    };

    void set_state(TcpState new_state);

    void emit_error(int error_code);

    void emit_closed(int event_code);

    void queue_segment(const TcpSegment& segment);

    void queue_control_segment(bool syn, bool ack, bool fin, bool rst);

    void queue_ack();

    void queue_payload_segment(const std::vector<uint8_t>& data);

    void handle_ack(uint32_t acknowledgment_number);

    void maybe_send_queued_fin();

    bool matches_peer(const TcpSegment& segment) const;

    int handle_reset();

    int handle_syn_sent(const TcpSegment& segment);

    int handle_established(const TcpSegment& segment);

    int handle_fin_wait_1(const TcpSegment& segment);

    int handle_fin_wait_2(const TcpSegment& segment);

    int handle_closing(const TcpSegment& segment);

    void enter_time_wait();

    uint16_t local_port_;
    uint16_t remote_port_;
    bool has_remote_port_;
    uint16_t advertised_window_;
    TcpState state_;

    uint32_t send_unacknowledged_;
    uint32_t send_next_;
    uint32_t receive_next_;
    uint32_t initial_sequence_number_;

    bool close_requested_;
    bool peer_closed_;
    uint32_t time_wait_remaining_ms_;

    std::vector<PendingTransmission> pending_transmissions_;
    std::vector<OutgoingSegment> outgoing_segments_;
    std::vector<ConnectionEvent> events_;
};

/**
 * @brief Returns a stable string name for one TcpState value.
 *
 * @param state TCP state value.
 * @return Null-terminated state name.
 */
const char* to_string(TcpState state);

}  // namespace mirage_tcp

#endif
