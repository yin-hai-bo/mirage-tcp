#ifndef MIRAGE_TCP_CHECKSUM_H
#define MIRAGE_TCP_CHECKSUM_H

#include <cstdint>
#include <cstddef>

namespace mirage_tcp {

struct Checksum {

    /**
     * @brief Calculate the checksum (one's complement sum) of the given memory block.
     *
     * @param dataptr       Pointer to the beginning of the memory block.
     * @param len           Length of the memory block.
     * @param additional    Additional value to be accumulated in the result (e.g., for segmented calculations).
     * @return uint16_t     The result.
     * @note Please note that this result is the 16-bit sum. If it is intended to be used as an IP or TCP header checksum,
     * it needs to be using the bitwise NOT operator '~'.
     */
    static uint16_t Calculate(const void * dataptr, size_t len, uint16_t additional = 0);
};

} // End of namespace

#endif
