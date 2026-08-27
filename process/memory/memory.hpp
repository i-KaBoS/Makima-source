#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace makima::process::memory {


class ProcessMemory final {
public:
    explicit ProcessMemory(void* process_handle) noexcept : process_handle_(process_handle) {}

    [[nodiscard]] void* process_handle() const noexcept { return process_handle_; }
    [[nodiscard]] bool valid() const noexcept { return process_handle_ != nullptr; }
    [[nodiscard]] std::size_t read(
        std::uintptr_t remote_address,
        std::span<std::byte> destination) const noexcept;
    [[nodiscard]] std::size_t write(
        std::uintptr_t remote_address,
        std::span<const std::byte> source) const noexcept;

private:
    void* process_handle_{};
};

struct TransferResult final {
    std::uintptr_t remote_address{};
    std::size_t requested{};
    std::size_t transferred{};
    [[nodiscard]] bool complete() const noexcept { return requested == transferred; }
};

class OwnedStorage final {
public:
    explicit OwnedStorage(std::size_t size = 0) : bytes_(size) {}
    [[nodiscard]] std::span<std::byte> bytes() noexcept { return bytes_; }
    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }
    void reset() noexcept;

private:
    std::vector<std::byte> bytes_;
};

[[nodiscard]] TransferResult read_remote_memory(
    const ProcessMemory& process,
    std::uintptr_t remote_address,
    std::span<std::byte> destination,
    std::size_t maximum_chunk = 0x1000);

[[nodiscard]] TransferResult write_remote_memory(
    const ProcessMemory& process,
    std::uintptr_t remote_address,
    std::span<const std::byte> source,
    std::size_t maximum_chunk = 0x1000);

void release_owned_storage(OwnedStorage& storage) noexcept;

}
