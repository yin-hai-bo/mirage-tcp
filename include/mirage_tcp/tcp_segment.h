#ifndef MIRAGE_TCP_TCP_SEGMENT_H
#define MIRAGE_TCP_TCP_SEGMENT_H

#include <cstdint>

#include <string>
#include <vector>

namespace mirage_tcp {

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;

/**
 * @brief Parsed TCP segment without options.
 */
struct TcpSegment {
    /** @brief Source TCP port. */
    uint16_t source_port;
    /** @brief Destination TCP port. */
    uint16_t destination_port;
    /** @brief TCP sequence number. */
    uint32_t sequence_number;
    /** @brief TCP acknowledgment number. */
    uint32_t acknowledgment_number;
    /** @brief Advertised TCP receive window. */
    uint16_t window_size;
    /** @brief SYN flag. */
    bool syn;
    /** @brief ACK flag. */
    bool ack;
    /** @brief FIN flag. */
    bool fin;
    /** @brief RST flag. */
    bool rst;
    /** @brief TCP payload bytes after the fixed header. */
    std::vector<uint8_t> payload;

    TcpSegment();
};

/**
 * @brief Parses one TCP segment without options.
 *
 * @param bytes Raw TCP segment bytes.
 * @param segment Output segment structure on success.
 * @param error_message Optional output error text on failure.
 * @return true if parsing succeeds; otherwise false.
 */
bool parse_tcp_segment(
    const std::vector<uint8_t>& bytes,
    TcpSegment* segment,
    std::string* error_message);

/**
 * @brief Serializes one TCP segment without checksum calculation.
 *
 * @param segment Parsed segment fields to serialize.
 * @return Serialized TCP segment bytes.
 */
std::vector<uint8_t> serialize_tcp_segment(const TcpSegment& segment);

}  // namespace mirage_tcp

#endif
