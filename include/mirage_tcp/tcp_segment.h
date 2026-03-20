#ifndef MIRAGE_TCP_TCP_SEGMENT_H
#define MIRAGE_TCP_TCP_SEGMENT_H

#include <cstddef>
#include <cstdint>

#include <vector>

#include "mirage_tcp/typedefs.h"
#include "mirage_tcp/error_code.h"

namespace mirage_tcp {

using std::size_t;
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
 * @brief Parses one TCP segment without options from a raw byte span.
 *
 * @param bytes Pointer to raw TCP segment bytes starting at the TCP header.
 *        This must point to the first byte immediately after the IP header,
 *        not to the beginning of the full IP packet. The caller guarantees
 *        that @p bytes is not null and is aligned to alignof(TcpHead).
 * @param byte_count Size of @p bytes in bytes.
 * @param out_segment Output segment structure on success.
 * @return 0 if parsing succeeds; otherwise an error code.
 */
error_code_t parse_tcp_segment(
    const void* bytes,
    size_t byte_count,
    TcpSegment& out_segment);

/**
 * @brief Serializes one TCP segment without checksum calculation.
 *
 * @param segment Parsed segment fields to serialize.
 * @return Serialized TCP segment bytes.
 */
std::vector<uint8_t> serialize_tcp_segment(const TcpSegment& segment);

}  // namespace mirage_tcp

#endif

