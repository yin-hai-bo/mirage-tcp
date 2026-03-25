#ifndef MIRAGE_TCP_CONNECTION_INFO_HPP
#define MIRAGE_TCP_CONNECTION_INFO_HPP

#include "mirage_tcp/mirage_tcp.h"

namespace mirage_tcp {

using ConnectionInfo = ::mirage_tcp_connection_info_t;

struct ConnectionInfoHash {
    size_t operator()(const mirage_tcp_connection_info_t & connection_info) const;
};

struct ConnectionInfoEqual {
    bool operator()(const mirage_tcp_connection_info_t & left, const mirage_tcp_connection_info_t & right) const;
};

} // namespace mirage_tcp

/**
 * @brief Strict weak ordering for using ConnectionInfo as a map key.
 */
bool operator<(const mirage_tcp_connection_info_t & left, const mirage_tcp_connection_info_t & right);

bool operator==(const mirage_tcp_connection_info_t & left, const mirage_tcp_connection_info_t & right);

inline bool operator != (const mirage_tcp_connection_info_t & left, const mirage_tcp_connection_info_t & right) {
    return !(left == right);
}


#endif
