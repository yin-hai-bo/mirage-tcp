#ifndef MIRAGE_TCP_PACKET_BUFFER_POOL_H
#define MIRAGE_TCP_PACKET_BUFFER_POOL_H

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace mirage_tcp {

class PacketBufferPool {
public:
    static constexpr std::size_t BUFFER_CAPACITY = 0xffffU;
    static constexpr std::size_t DEFAULT_POOL_SIZE = 4U;

    explicit PacketBufferPool(std::size_t slot_count = DEFAULT_POOL_SIZE);
    ~PacketBufferPool();

    PacketBufferPool(const PacketBufferPool&) = delete;
    PacketBufferPool& operator=(const PacketBufferPool&) = delete;

    std::uint8_t* acquire();
    void release(std::uint8_t* bytes);

private:
    struct Slot {
        Slot* next;
        std::uint8_t bytes[BUFFER_CAPACITY];
    };

    std::vector<Slot*> slots_;
    Slot* free_list_;
};

class PacketBufferLease {
public:
    explicit PacketBufferLease(PacketBufferPool& pool);
    ~PacketBufferLease();

    PacketBufferLease(const PacketBufferLease&) = delete;
    PacketBufferLease& operator=(const PacketBufferLease&) = delete;

    std::uint8_t* data();

private:

    struct FallbackDeleter {
        void operator()(std::uint8_t* bytes) const;
    };

    PacketBufferPool& pool_;
    std::uint8_t* pooled_bytes_;
    std::unique_ptr<std::uint8_t, FallbackDeleter> fallback_;
};

}  // namespace mirage_tcp

#endif
