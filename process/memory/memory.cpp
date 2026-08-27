#include "process/memory/memory.hpp"

#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

namespace makima::process::memory {
namespace {

template <typename ByteSpan, typename TransferOperation>
TransferResult transfer_in_chunks(
    std::uintptr_t remote_address,
    ByteSpan bytes,
    std::size_t maximum_chunk,
    TransferOperation&& transfer) {
    TransferResult result{remote_address, bytes.size(), 0};
    if (bytes.empty()) {
        return result;
    }
    const auto chunk_limit = maximum_chunk == 0 ? bytes.size() : maximum_chunk;
    while (result.transferred < result.requested) {
        const auto remaining = result.requested - result.transferred;
        const auto chunk_size = std::min(remaining, chunk_limit);
        const auto chunk = bytes.subspan(result.transferred, chunk_size);
        const auto bytes_transferred =
            transfer(remote_address + result.transferred, chunk);
        if (bytes_transferred > chunk_size) {

            break;
        }
        result.transferred += bytes_transferred;
        if (bytes_transferred != chunk_size) {
            break;
        }
    }
    return result;
}

}

std::size_t ProcessMemory::read(
    std::uintptr_t remote_address,
    std::span<std::byte> destination) const noexcept {
    if (!valid() || remote_address == 0 || destination.empty()) {
        return 0;
    }

    SIZE_T transferred = 0;
    const auto succeeded = ReadProcessMemory(
        static_cast<HANDLE>(process_handle_),
        reinterpret_cast<const void*>(remote_address),
        destination.data(),
        destination.size(),
        &transferred);
    return succeeded ? static_cast<std::size_t>(transferred) : 0;
}

std::size_t ProcessMemory::write(
    std::uintptr_t remote_address,
    std::span<const std::byte> source) const noexcept {
    if (!valid() || remote_address == 0 || source.empty()) {
        return 0;
    }

    SIZE_T transferred = 0;
    const auto succeeded = WriteProcessMemory(
        static_cast<HANDLE>(process_handle_),
        reinterpret_cast<void*>(remote_address),
        source.data(),
        source.size(),
        &transferred);
    return succeeded ? static_cast<std::size_t>(transferred) : 0;
}


TransferResult read_remote_memory(
    const ProcessMemory& process,
    std::uintptr_t remote_address,
    std::span<std::byte> destination,
    std::size_t maximum_chunk) {
    return transfer_in_chunks(
        remote_address,
        destination,
        maximum_chunk,
        [&](std::uintptr_t address, std::span<std::byte> chunk) {
            return process.read(address, chunk);
        });
}




TransferResult write_remote_memory(
    const ProcessMemory& process,
    std::uintptr_t remote_address,
    std::span<const std::byte> source,
    std::size_t maximum_chunk) {
    return transfer_in_chunks(
        remote_address,
        source,
        maximum_chunk,
        [&](std::uintptr_t address, std::span<const std::byte> chunk) {
            return process.write(address, chunk);
        });
}

void OwnedStorage::reset() noexcept {
    std::fill(bytes_.begin(), bytes_.end(), std::byte{});
    bytes_.clear();
    bytes_.shrink_to_fit();
}




void release_owned_storage(OwnedStorage& storage) noexcept {
    storage.reset();
}

}
