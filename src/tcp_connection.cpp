#include "mirage_tcp/tcp_connection.h"

namespace mirage_tcp {

namespace {

uint32_t sequence_span(const TcpSegment& segment) {
    uint32_t span = static_cast<uint32_t>(segment.payload.size());
    if (segment.syn) {
        ++span;
    }
    if (segment.fin) {
        ++span;
    }
    return span;
}

}  // namespace

TcpConnection::TcpConnection(
    uint16_t local_port,
    uint32_t initial_sequence_number,
    uint16_t advertised_window)
    : local_port_(local_port),
      remote_port_(0),
      has_remote_port_(false),
      advertised_window_(advertised_window),
      state_(TcpState::kClosed),
      send_unacknowledged_(initial_sequence_number),
      send_next_(initial_sequence_number),
      receive_next_(0),
      initial_sequence_number_(initial_sequence_number),
      close_requested_(false),
      peer_closed_(false),
      time_wait_remaining_ms_(0) {}

error_code_t TcpConnection::connect(uint16_t remote_port) {
    if (state_ != TcpState::kClosed) {
        emit_error(ErrorCode::ConnectInvalidState);
        return ErrorCode::ConnectInvalidState;
    }

    remote_port_ = remote_port;
    has_remote_port_ = true;
    close_requested_ = false;
    peer_closed_ = false;
    time_wait_remaining_ms_ = 0;
    pending_transmissions_.clear();
    send_unacknowledged_ = initial_sequence_number_;
    send_next_ = initial_sequence_number_;
    queue_control_segment(true, false, false, false);
    set_state(TcpState::kSynSent);
    return ErrorCode::Ok;
}

error_code_t TcpConnection::write(const std::vector<uint8_t>& data) {
    if (state_ != TcpState::kEstablished) {
        emit_error(ErrorCode::WriteInvalidState);
        return ErrorCode::WriteInvalidState;
    }

    if (close_requested_ || peer_closed_) {
        emit_error(ErrorCode::WriteAfterClose);
        return ErrorCode::WriteAfterClose;
    }

    if (data.empty()) {
        return ErrorCode::Ok;
    }

    queue_payload_segment(data);
    return ErrorCode::Ok;
}

error_code_t TcpConnection::close() {
    if (state_ != TcpState::kEstablished && state_ != TcpState::kFinWait1 && state_ != TcpState::kFinWait2) {
        emit_error(ErrorCode::CloseInvalidState);
        return ErrorCode::CloseInvalidState;
    }

    close_requested_ = true;
    maybe_send_queued_fin();
    return ErrorCode::Ok;
}

error_code_t TcpConnection::push_incoming_segment(const TcpSegment& segment) {
    if (!matches_peer(segment)) {
        emit_error(ErrorCode::PeerMismatch);
        return ErrorCode::PeerMismatch;
    }

    if (segment.rst) {
        return handle_reset();
    }

    switch (state_) {
        case TcpState::kClosed:
            emit_error(ErrorCode::ClosedState);
            return ErrorCode::ClosedState;
        case TcpState::kSynSent:
            return handle_syn_sent(segment);
        case TcpState::kEstablished:
            return handle_established(segment);
        case TcpState::kFinWait1:
            return handle_fin_wait_1(segment);
        case TcpState::kFinWait2:
            return handle_fin_wait_2(segment);
        case TcpState::kClosing:
            return handle_closing(segment);
        case TcpState::kTimeWait:
            if (segment.fin) {
                queue_ack();
            }
            return ErrorCode::Ok;
    }

    emit_error(ErrorCode::UnhandledState);
    return ErrorCode::UnhandledState;
}

error_code_t TcpConnection::push_incoming_bytes(const std::vector<uint8_t>& bytes) {
    TcpSegment segment;
    const error_code_t parse_result = parse_tcp_segment(bytes, &segment);
    if (parse_result != ErrorCode::Ok) {
        return parse_result;
    }
    return push_incoming_segment(segment);
}

void TcpConnection::tick(uint32_t elapsed_ms) {
    if (state_ != TcpState::kTimeWait) {
        return;
    }

    if (elapsed_ms >= time_wait_remaining_ms_) {
        time_wait_remaining_ms_ = 0;
        set_state(TcpState::kClosed);
        emit_closed(ErrorCode::TimeWaitExpired);
        return;
    }

    time_wait_remaining_ms_ -= elapsed_ms;
}

std::vector<OutgoingSegment> TcpConnection::drain_outgoing() {
    std::vector<OutgoingSegment> drained = outgoing_segments_;
    outgoing_segments_.clear();
    return drained;
}

std::vector<ConnectionEvent> TcpConnection::drain_events() {
    std::vector<ConnectionEvent> drained = events_;
    events_.clear();
    return drained;
}

TcpState TcpConnection::state() const {
    return state_;
}

uint16_t TcpConnection::local_port() const {
    return local_port_;
}

uint16_t TcpConnection::remote_port() const {
    return remote_port_;
}

bool TcpConnection::has_remote_port() const {
    return has_remote_port_;
}

void TcpConnection::set_state(TcpState new_state) {
    if (state_ == new_state) {
        return;
    }

    state_ = new_state;
    ConnectionEvent event;
    event.type = ConnectionEventType::kStateChanged;
    event.state = new_state;
    event.event_code = ErrorCode::Ok;
    events_.push_back(event);
}

void TcpConnection::emit_error(error_code_t error_code) {
    ConnectionEvent event;
    event.type = ConnectionEventType::kError;
    event.state = state_;
    event.event_code = error_code;
    events_.push_back(event);
}

void TcpConnection::emit_closed(error_code_t event_code) {
    ConnectionEvent event;
    event.type = ConnectionEventType::kConnectionClosed;
    event.state = state_;
    event.event_code = event_code;
    events_.push_back(event);
}

void TcpConnection::queue_segment(const TcpSegment& segment) {
    OutgoingSegment outgoing;
    outgoing.segment = segment;
    outgoing.bytes = serialize_tcp_segment(segment);
    outgoing_segments_.push_back(outgoing);
}

void TcpConnection::queue_control_segment(bool syn, bool ack, bool fin, bool rst) {
    TcpSegment segment;
    segment.source_port = local_port_;
    segment.destination_port = remote_port_;
    segment.sequence_number = send_next_;
    segment.acknowledgment_number = ack ? receive_next_ : 0;
    segment.window_size = advertised_window_;
    segment.syn = syn;
    segment.ack = ack;
    segment.fin = fin;
    segment.rst = rst;
    queue_segment(segment);

    const uint32_t span = sequence_span(segment);
    if (span > 0) {
        PendingTransmission transmission;
        transmission.sequence_begin = send_next_;
        transmission.sequence_end = send_next_ + span;
        transmission.fin = fin;
        pending_transmissions_.push_back(transmission);
        send_next_ += span;
    }
}

void TcpConnection::queue_ack() {
    TcpSegment segment;
    segment.source_port = local_port_;
    segment.destination_port = remote_port_;
    segment.sequence_number = send_next_;
    segment.acknowledgment_number = receive_next_;
    segment.window_size = advertised_window_;
    segment.ack = true;
    queue_segment(segment);
}

void TcpConnection::queue_payload_segment(const std::vector<uint8_t>& data) {
    TcpSegment segment;
    segment.source_port = local_port_;
    segment.destination_port = remote_port_;
    segment.sequence_number = send_next_;
    segment.acknowledgment_number = receive_next_;
    segment.window_size = advertised_window_;
    segment.ack = true;
    segment.payload = data;
    queue_segment(segment);

    PendingTransmission transmission;
    transmission.sequence_begin = send_next_;
    transmission.sequence_end = send_next_ + static_cast<uint32_t>(data.size());
    transmission.fin = false;
    pending_transmissions_.push_back(transmission);
    send_next_ = transmission.sequence_end;
}

void TcpConnection::handle_ack(uint32_t acknowledgment_number) {
    if (acknowledgment_number <= send_unacknowledged_ || acknowledgment_number > send_next_) {
        return;
    }

    send_unacknowledged_ = acknowledgment_number;

    while (!pending_transmissions_.empty() &&
           pending_transmissions_.front().sequence_end <= acknowledgment_number) {
        const bool acknowledged_fin = pending_transmissions_.front().fin;
        pending_transmissions_.erase(pending_transmissions_.begin());

        if (acknowledged_fin) {
            if (state_ == TcpState::kFinWait1) {
                set_state(TcpState::kFinWait2);
            } else if (state_ == TcpState::kClosing) {
                enter_time_wait();
            }
        }
    }

    maybe_send_queued_fin();
}

void TcpConnection::maybe_send_queued_fin() {
    if (!close_requested_ || peer_closed_) {
        return;
    }
    if (state_ != TcpState::kEstablished) {
        return;
    }
    if (!pending_transmissions_.empty()) {
        return;
    }

    queue_control_segment(false, true, true, false);
    set_state(TcpState::kFinWait1);
}

bool TcpConnection::matches_peer(const TcpSegment& segment) const {
    if (!has_remote_port_) {
        return segment.destination_port == local_port_;
    }

    return segment.destination_port == local_port_ &&
           segment.source_port == remote_port_;
}

error_code_t TcpConnection::handle_reset() {
    pending_transmissions_.clear();
    close_requested_ = true;
    peer_closed_ = true;
    set_state(TcpState::kClosed);
    emit_closed(ErrorCode::ClosedByReset);
    return ErrorCode::Ok;
}

error_code_t TcpConnection::handle_syn_sent(const TcpSegment& segment) {
    if (!segment.syn || !segment.ack) {
        emit_error(ErrorCode::SynAckExpected);
        return ErrorCode::SynAckExpected;
    }

    if (segment.acknowledgment_number != send_next_) {
        emit_error(ErrorCode::AckUnexpected);
        return ErrorCode::AckUnexpected;
    }

    handle_ack(segment.acknowledgment_number);
    receive_next_ = segment.sequence_number + 1;
    queue_ack();
    set_state(TcpState::kEstablished);
    return ErrorCode::Ok;
}

error_code_t TcpConnection::handle_established(const TcpSegment& segment) {
    if (segment.ack) {
        handle_ack(segment.acknowledgment_number);
    }

    if (!segment.payload.empty()) {
        if (segment.sequence_number != receive_next_) {
            queue_ack();
            emit_error(ErrorCode::PayloadOutOfOrder);
            return ErrorCode::PayloadOutOfOrder;
        }

        receive_next_ += static_cast<uint32_t>(segment.payload.size());
        ConnectionEvent event;
        event.type = ConnectionEventType::kDataReceived;
        event.state = state_;
        event.data = segment.payload;
        event.event_code = ErrorCode::Ok;
        events_.push_back(event);
        queue_ack();
    }

    if (segment.fin) {
        if (segment.sequence_number + static_cast<uint32_t>(segment.payload.size()) != receive_next_) {
            emit_error(ErrorCode::FinSequenceUnexpected);
            return ErrorCode::FinSequenceUnexpected;
        }

        peer_closed_ = true;
        ++receive_next_;
        queue_ack();
        set_state(TcpState::kTimeWait);
        time_wait_remaining_ms_ = 2000;
        emit_closed(ErrorCode::ClosedByPeerFin);
    }

    return ErrorCode::Ok;
}

error_code_t TcpConnection::handle_fin_wait_1(const TcpSegment& segment) {
    if (segment.ack) {
        handle_ack(segment.acknowledgment_number);
    }

    if (!segment.payload.empty()) {
        if (segment.sequence_number != receive_next_) {
            queue_ack();
            emit_error(ErrorCode::PayloadOutOfOrder);
            return ErrorCode::PayloadOutOfOrder;
        }

        receive_next_ += static_cast<uint32_t>(segment.payload.size());
        ConnectionEvent event;
        event.type = ConnectionEventType::kDataReceived;
        event.state = state_;
        event.data = segment.payload;
        event.event_code = ErrorCode::Ok;
        events_.push_back(event);
        queue_ack();
    }

    if (segment.fin) {
        if (segment.sequence_number + static_cast<uint32_t>(segment.payload.size()) != receive_next_) {
            emit_error(ErrorCode::FinSequenceUnexpected);
            return ErrorCode::FinSequenceUnexpected;
        }

        ++receive_next_;
        queue_ack();
        if (state_ == TcpState::kFinWait2) {
            enter_time_wait();
        } else {
            set_state(TcpState::kClosing);
        }
    }

    return ErrorCode::Ok;
}

error_code_t TcpConnection::handle_fin_wait_2(const TcpSegment& segment) {
    if (segment.ack) {
        handle_ack(segment.acknowledgment_number);
    }

    if (segment.fin) {
        if (segment.sequence_number != receive_next_) {
            queue_ack();
            emit_error(ErrorCode::FinSequenceUnexpected);
            return ErrorCode::FinSequenceUnexpected;
        }

        ++receive_next_;
        queue_ack();
        enter_time_wait();
    }

    return ErrorCode::Ok;
}

error_code_t TcpConnection::handle_closing(const TcpSegment& segment) {
    if (segment.ack) {
        handle_ack(segment.acknowledgment_number);
    }

    if (segment.fin) {
        queue_ack();
    }

    return ErrorCode::Ok;
}

void TcpConnection::enter_time_wait() {
    set_state(TcpState::kTimeWait);
    time_wait_remaining_ms_ = 2000;
}

const char* to_string(TcpState state) {
    switch (state) {
        case TcpState::kClosed:
            return "CLOSED";
        case TcpState::kSynSent:
            return "SYN-SENT";
        case TcpState::kEstablished:
            return "ESTABLISHED";
        case TcpState::kFinWait1:
            return "FIN-WAIT-1";
        case TcpState::kFinWait2:
            return "FIN-WAIT-2";
        case TcpState::kClosing:
            return "CLOSING";
        case TcpState::kTimeWait:
            return "TIME-WAIT";
    }

    return "UNKNOWN";
}

}  // namespace mirage_tcp

