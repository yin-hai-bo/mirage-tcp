#include <cstddef>
#include <cstdint>
#include <vector>

#include "mirage_tcp/checksum.h"
#include "test_harness.h"

namespace {

uint16_t reference_checksum_sum(const void* dataptr, std::size_t len, uint16_t additional = 0) {
    const uint8_t* bytes = static_cast<const uint8_t*>(dataptr);
    uint32_t sum = additional;

    while (len >= 2) {
        sum += static_cast<uint16_t>(
            (static_cast<uint16_t>(bytes[0]) << 8) |
            static_cast<uint16_t>(bytes[1]));
        bytes += 2;
        len -= 2;
    }

    if (len > 0) {
        sum += static_cast<uint16_t>(static_cast<uint16_t>(bytes[0]) << 8);
    }

    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return static_cast<uint16_t>(sum);
}

void test_checksum_matches_reference_for_even_length() {
    const uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0};
    require(
        mirage_tcp::Checksum::Calculate(bytes, sizeof(bytes)) == reference_checksum_sum(bytes, sizeof(bytes)),
        "even-length checksum should match reference");
}

void test_checksum_matches_reference_for_odd_length() {
    const uint8_t bytes[] = {0x01, 0x23, 0x45, 0x67, 0x89};
    require(
        mirage_tcp::Checksum::Calculate(bytes, sizeof(bytes)) == reference_checksum_sum(bytes, sizeof(bytes)),
        "odd-length checksum should match reference");
}

void test_checksum_matches_reference_for_unaligned_input() {
    const uint8_t storage[] = {0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    const uint8_t* bytes = storage + 1;
    const std::size_t len = sizeof(storage) - 1;
    require(
        mirage_tcp::Checksum::Calculate(bytes, len) == reference_checksum_sum(bytes, len),
        "unaligned checksum should match reference");
}

void test_checksum_accumulates_additional_sum() {
    const uint8_t bytes[] = {0xab, 0xcd, 0xef, 0x01};
    const uint16_t additional = 0x1357;
    require(
        mirage_tcp::Checksum::Calculate(bytes, sizeof(bytes), additional) ==
            reference_checksum_sum(bytes, sizeof(bytes), additional),
        "checksum with additional sum should match reference");
}

}  // namespace

void append_checksum_tests(std::vector<TestCase>* tests) {
    tests->push_back(TestCase{"checksum_even_length", test_checksum_matches_reference_for_even_length});
    tests->push_back(TestCase{"checksum_odd_length", test_checksum_matches_reference_for_odd_length});
    tests->push_back(TestCase{"checksum_unaligned_input", test_checksum_matches_reference_for_unaligned_input});
    tests->push_back(TestCase{"checksum_additional_sum", test_checksum_accumulates_additional_sum});
}
