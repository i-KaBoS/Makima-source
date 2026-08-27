#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace makima::process::execution {

struct RemoteExecutionDescriptor final {
    void* process_handle{};
    std::uintptr_t routine{};
    std::uintptr_t argument{};
    std::uintptr_t result_storage{};

    [[nodiscard]] bool valid() const noexcept {
        return process_handle != nullptr && routine != 0;
    }
};

void abort_remote_thread_initialization() noexcept;
void abort_remote_allocation_initialization() noexcept;
void abort_parameter_block_initialization() noexcept;
void abort_trampoline_initialization() noexcept;
void abort_thread_context_initialization() noexcept;
void abort_completion_event_initialization() noexcept;
void abort_process_handle_initialization() noexcept;


[[nodiscard]] std::array<std::byte, 23> make_absolute_jump_thunk(
    std::uint64_t rax_value,
    std::uintptr_t destination) noexcept;

}
