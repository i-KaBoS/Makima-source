#include "process/execution/execution.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace makima::process::execution {
namespace {

void write_little_endian_u64(
    std::array<std::byte, 23>& bytes,
    std::size_t offset,
    std::uint64_t value) noexcept {
    for (std::size_t byte_index = 0; byte_index < sizeof(value); ++byte_index) {
        bytes[offset + byte_index] =
            static_cast<std::byte>(value >> (byte_index * 8U));
    }
}

}


std::array<std::byte, 23> make_absolute_jump_thunk(
    std::uint64_t rax_value,
    std::uintptr_t destination) noexcept {
    std::array<std::byte, 23> instruction_bytes{};


    instruction_bytes[0] = std::byte{0x48};
    instruction_bytes[1] = std::byte{0xB8};
    write_little_endian_u64(instruction_bytes, 2, rax_value);


    instruction_bytes[10] = std::byte{0x49};
    instruction_bytes[11] = std::byte{0xBB};
    write_little_endian_u64(
        instruction_bytes, 12, static_cast<std::uint64_t>(destination));


    instruction_bytes[20] = std::byte{0x41};
    instruction_bytes[21] = std::byte{0xFF};
    instruction_bytes[22] = std::byte{0xE3};
    return instruction_bytes;
}

}
