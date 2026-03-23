#include "packet_buffer_pool.h"

#include <cstdlib>

namespace mirage_tcp {

void PacketBufferLease::FallbackDeleter::operator()(std::uint8_t* bytes) const {
    std::free(bytes);
}

PacketBufferPool::PacketBufferPool(std::size_t slot_count)
    : free_list_(nullptr)
{
    slots_.reserve(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i) {
        Slot* slot = new Slot();
        slot->next = free_list_;
        free_list_ = slot;
        slots_.push_back(slot);
    }
}

PacketBufferPool::~PacketBufferPool() {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
        delete slots_[i];
    }
}

std::uint8_t* PacketBufferPool::acquire() {
    if (free_list_ == nullptr) {
        return nullptr;
    }

    Slot* slot = free_list_;
    free_list_ = free_list_->next;
    slot->next = nullptr;
    return slot->bytes;
}

void PacketBufferPool::release(std::uint8_t* bytes) {
    if (bytes == nullptr) {
        return;
    }

    for (std::size_t i = 0; i < slots_.size(); ++i) {
        if (slots_[i]->bytes == bytes) {
            slots_[i]->next = free_list_;
            free_list_ = slots_[i];
            return;
        }
    }
}

PacketBufferLease::PacketBufferLease(PacketBufferPool& pool)
    : pool_(pool),
      pooled_bytes_(pool_.acquire())
{}

PacketBufferLease::~PacketBufferLease() {
    if (pooled_bytes_ != nullptr) {
        pool_.release(pooled_bytes_);
    }
}

std::uint8_t* PacketBufferLease::data() {
    if (pooled_bytes_ != nullptr) {
        return pooled_bytes_;
    }

    if (!fallback_) {
        fallback_.reset(static_cast<std::uint8_t*>(std::malloc(PacketBufferPool::BUFFER_CAPACITY)));
    }
    return fallback_.get();
}

}  // namespace mirage_tcp
