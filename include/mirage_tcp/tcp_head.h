#ifndef MIRAGE_TCP_TCP_HEAD_H
#define MIRAGE_TCP_TCP_HEAD_H

#include <cstdint>

namespace mirage_tcp {

using std::uint16_t;
using std::uint32_t;
using std::uint8_t;

/**
 * @brief Fixed TCP header bytes in network byte order.
 */
struct TcpHead {
    uint16_t source_port;
    uint16_t destination_port;
    uint32_t sequence_number;
    uint32_t acknowledgment_number;
    uint8_t data_offset_reserved;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

static_assert(sizeof(TcpHead) == 20, "TcpHead must match the fixed TCP header size");

}  // namespace mirage_tcp

#endif
