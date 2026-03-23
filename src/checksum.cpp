#include "mirage_tcp/checksum.h"

namespace {

uint32_t fold_u32(uint32_t value) {
    return (value >> 16) + (value & 0x0000ffffUL);
}

uint16_t read_u16_be(const uint8_t* bytes) {

#if defined(_WIN32) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))

    return static_cast<uint16_t>(
        (static_cast<uint16_t>(bytes[0]) << 8) |
        static_cast<uint16_t>(bytes[1]));

#else

    // Compilers typically lower this fixed-size memcpy to a single load.
    uint16_t word;
    std::memcpy(&word, bytes, sizeof(word));
    return word;

#endif

}

}  // namespace

uint16_t mirage_tcp::Checksum::Calculate(const void* dataptr, size_t len, uint16_t additional) {
    const uint8_t* bytes = static_cast<const uint8_t*>(dataptr);
    uint32_t sum = additional;

    // Keep the hot loop branch-light and alias-safe by consuming 8 bytes
    // per iteration without reinterpreting the backing storage.
    while (len >= 8) {
        sum += read_u16_be(bytes);
        sum += read_u16_be(bytes + 2);
        sum += read_u16_be(bytes + 4);
        sum += read_u16_be(bytes + 6);
        bytes += 8;
        len -= 8;
    }

    while (len >= 2) {
        sum += read_u16_be(bytes);
        bytes += 2;
        len -= 2;
    }

    if (len > 0) {
        sum += static_cast<uint16_t>(static_cast<uint16_t>(bytes[0]) << 8);
    }

    sum = fold_u32(sum);
    sum = fold_u32(sum);
    return static_cast<uint16_t>(sum);
}
