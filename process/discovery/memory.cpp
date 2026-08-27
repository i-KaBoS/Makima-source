#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "process/discovery/discovery.hpp"

namespace makima::process::discovery {


char* allocate_create_event_w(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "CreateEventW";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_set_event(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "SetEvent";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_wait_for_single_object(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr char decoded_value[] = "WaitForSingleObject";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll_for_wait_for_single_object(
    std::int64_t source) {
    (void)source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_sleep_api_name(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "Sleep";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_for_sleep(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_enum_windows_api_name(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "EnumWindows";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_user32_for_enum_windows(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "user32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}

namespace {

enum class ByteOperation : std::uint8_t {
    identity,
    xor_value,
    add,
    subtract,
    reverse_subtract,
};

struct ByteFormula final {
    ByteOperation first_operation;
    std::uint8_t first_key;
    ByteOperation second_operation;
    std::uint8_t second_key;
    ByteOperation third_operation;
    std::uint8_t third_key;
    unsigned rotation_count;
    ByteOperation final_operation;
    std::uint8_t final_key;
};

std::uint8_t apply_byte_operation(
    std::uint8_t value,
    ByteOperation operation,
    std::uint8_t key) noexcept {
    switch (operation) {
    case ByteOperation::identity:
        return value;
    case ByteOperation::xor_value:
        return static_cast<std::uint8_t>(value ^ key);
    case ByteOperation::add:
        return static_cast<std::uint8_t>(value + key);
    case ByteOperation::subtract:
        return static_cast<std::uint8_t>(value - key);
    case ByteOperation::reverse_subtract:
        return static_cast<std::uint8_t>(key - value);
    }
    return value;
}

std::uint8_t rotate_byte_left(
    std::uint8_t value,
    unsigned count) noexcept {
    count &= 7U;
    if (count == 0) return value;
    return static_cast<std::uint8_t>(
        (value << count) | (value >> (8U - count)));
}

std::uint8_t apply_byte_formula(
    std::uint8_t value,
    const ByteFormula& formula) noexcept {
    value = apply_byte_operation(
        value, formula.first_operation, formula.first_key);
    value = apply_byte_operation(
        value, formula.second_operation, formula.second_key);
    value = apply_byte_operation(
        value, formula.third_operation, formula.third_key);
    value = rotate_byte_left(value, formula.rotation_count);
    return apply_byte_operation(
        value, formula.final_operation, formula.final_key);
}

template <std::size_t Size>
std::byte* decode_bytes(
    const std::byte* source,
    const std::array<ByteFormula, Size>& schedule) {
    auto* output = static_cast<std::byte*>(::operator new(Size + 1U));
    for (std::size_t index = 0; index < Size; ++index) {
        output[index] = static_cast<std::byte>(apply_byte_formula(
            std::to_integer<std::uint8_t>(source[index]),
            schedule[index]));
    }
    output[Size] = std::byte{};
    return output;
}

}


std::byte* decode_protected_bytes_1402dc500(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xA9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xC3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x27},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xE8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xED},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x72},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x50},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x28},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x22},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x11},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x17},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xB2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x96},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x77},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x6F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x41},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xA5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x78},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xF0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xBB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x18},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xA3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xFC},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402de500(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x4F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x83},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x15},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xCD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x23},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x26},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xD6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x89},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x64},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xF7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x5B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x37},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x76},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xE6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x67},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402e0700(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x12},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xF0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xE6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xEE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x12},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xEA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xE8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xEE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xFA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x12},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x83},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402e31a0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x56, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::add, 0x30, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::add, 0x38, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::add, 0x5B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xEE},
                ByteFormula{ByteOperation::add, 0x5B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xDD},
                ByteFormula{ByteOperation::add, 0xC, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xF7},
                ByteFormula{ByteOperation::add, 0x4B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xEF},
                ByteFormula{ByteOperation::add, 0x10, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xBB},
                ByteFormula{ByteOperation::add, 0x5D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xD1},
                ByteFormula{ByteOperation::add, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x58},
                ByteFormula{ByteOperation::add, 0x36, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x30},
                ByteFormula{ByteOperation::add, 0x54, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xCF},
                ByteFormula{ByteOperation::add, 0x6C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xBF},
                ByteFormula{ByteOperation::add, 0x2F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x35},
                ByteFormula{ByteOperation::add, 0x2B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xE9},
                ByteFormula{ByteOperation::add, 0x19, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x59},
                ByteFormula{ByteOperation::add, 0xD, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x8B},
                ByteFormula{ByteOperation::add, 0x7A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::add, 0x50, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xBF},
                ByteFormula{ByteOperation::add, 0x56, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::add, 0x3, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::add, 0x78, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xF},
                ByteFormula{ByteOperation::add, 0x14, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::add, 0x12, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x96},
                ByteFormula{ByteOperation::add, 0x63, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x6B},
                ByteFormula{ByteOperation::add, 0x24, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::add, 0x69, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x6E},
                ByteFormula{ByteOperation::add, 0x16, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::add, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::add, 0x38, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::add, 0x6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x6C},
                ByteFormula{ByteOperation::add, 0xC, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xDF},
                ByteFormula{ByteOperation::add, 0x3C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::add, 0xB, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xAF},
                ByteFormula{ByteOperation::add, 0x52, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::add, 0x6C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xBF},
                ByteFormula{ByteOperation::add, 0x3D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x11},
                ByteFormula{ByteOperation::add, 0x2B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x9E},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402e5610(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x3C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xE2},
                ByteFormula{ByteOperation::add, 0xB, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x80},
                ByteFormula{ByteOperation::add, 0x5A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x26},
                ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xFC},
                ByteFormula{ByteOperation::add, 0x4B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::add, 0x62, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAC},
                ByteFormula{ByteOperation::add, 0x8, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x9A},
                ByteFormula{ByteOperation::add, 0x54, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x64},
                ByteFormula{ByteOperation::add, 0x26, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6F},
                ByteFormula{ByteOperation::add, 0x9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x42},
                ByteFormula{ByteOperation::add, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x7A},
                ByteFormula{ByteOperation::add, 0x76, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x3F},
                ByteFormula{ByteOperation::add, 0x3B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::add, 0x44, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x9},
                ByteFormula{ByteOperation::add, 0x2A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x1B},
                ByteFormula{ByteOperation::add, 0x5D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::add, 0x60, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xA8},
                ByteFormula{ByteOperation::add, 0xF, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x22},
                ByteFormula{ByteOperation::add, 0x5A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x98},
                ByteFormula{ByteOperation::add, 0x2D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x33},
                ByteFormula{ByteOperation::add, 0x4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x5B},
                ByteFormula{ByteOperation::add, 0x48, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::add, 0x7, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC4},
                ByteFormula{ByteOperation::add, 0x79, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::add, 0x6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x3D},
                ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::add, 0x28, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::add, 0x21, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xA6},
                ByteFormula{ByteOperation::add, 0x51, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::add, 0x1F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x8A},
                ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::add, 0x42, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x61},
                ByteFormula{ByteOperation::add, 0x4F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x80},
                ByteFormula{ByteOperation::add, 0x2D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xCC},
                ByteFormula{ByteOperation::add, 0x45, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC1},
                ByteFormula{ByteOperation::add, 0xF, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x88},
                ByteFormula{ByteOperation::add, 0x4B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::add, 0x21, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x4D},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402e80a0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::xor_value, 0x7, ByteOperation::add, 0x3B, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x4C},
                ByteFormula{ByteOperation::xor_value, 0x36, ByteOperation::reverse_subtract, 0x75, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x12},
                ByteFormula{ByteOperation::xor_value, 0x1A, ByteOperation::reverse_subtract, 0xD8, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::xor_value, 0xA, ByteOperation::reverse_subtract, 0xCB, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::xor_value, 0x3C, ByteOperation::add, 0x1, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x47},
                ByteFormula{ByteOperation::xor_value, 0x43, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x13},
                ByteFormula{ByteOperation::xor_value, 0x99, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x19},
                ByteFormula{ByteOperation::xor_value, 0xF2, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0xDE},
                ByteFormula{ByteOperation::xor_value, 0xE, ByteOperation::reverse_subtract, 0xCD, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::xor_value, 0x10, ByteOperation::add, 0xAD, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4B},
                ByteFormula{ByteOperation::xor_value, 0x22, ByteOperation::add, 0x10, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x3},
                ByteFormula{ByteOperation::xor_value, 0x1, ByteOperation::reverse_subtract, 0xC2, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x21},
                ByteFormula{ByteOperation::xor_value, 0xC5, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0x3A},
                ByteFormula{ByteOperation::add, 0x40, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x44},
                ByteFormula{ByteOperation::xor_value, 0x33, ByteOperation::reverse_subtract, 0xF0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x13},
                ByteFormula{ByteOperation::xor_value, 0x35, ByteOperation::reverse_subtract, 0x75, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x11},
                ByteFormula{ByteOperation::xor_value, 0x15, ByteOperation::add, 0x29, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::xor_value, 0x1F, ByteOperation::add, 0xA4, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x44},
                ByteFormula{ByteOperation::xor_value, 0x28, ByteOperation::add, 0x96, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::xor_value, 0xC4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::add, 0x88},
                ByteFormula{ByteOperation::xor_value, 0x2F, ByteOperation::reverse_subtract, 0xEB, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x3},
                ByteFormula{ByteOperation::xor_value, 0x25, ByteOperation::reverse_subtract, 0x66, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1},
                ByteFormula{ByteOperation::xor_value, 0x68, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::add, 0x8B},
                ByteFormula{ByteOperation::xor_value, 0x3C, ByteOperation::reverse_subtract, 0xFE, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::xor_value, 0x27, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::add, 0x7C},
                ByteFormula{ByteOperation::xor_value, 0x3A, ByteOperation::add, 0x6, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x60},
                ByteFormula{ByteOperation::xor_value, 0x6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0xF2},
                ByteFormula{ByteOperation::xor_value, 0x4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0xD},
                ByteFormula{ByteOperation::xor_value, 0x10, ByteOperation::reverse_subtract, 0x52, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::xor_value, 0x2E, ByteOperation::add, 0x12, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x74},
                ByteFormula{ByteOperation::xor_value, 0x10, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0x1D},
                ByteFormula{ByteOperation::xor_value, 0x4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0x5A},
                ByteFormula{ByteOperation::xor_value, 0x1, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0xA3},
                ByteFormula{ByteOperation::xor_value, 0xA0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x94},
                ByteFormula{ByteOperation::xor_value, 0x34, ByteOperation::add, 0x8C, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x60},
                ByteFormula{ByteOperation::xor_value, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x73},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402ebab0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x8A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x94},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x9E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x85},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xBC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x61},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xD5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x9E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x94},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xE5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xB9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x1A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x75},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x52},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402ed7c0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x26},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x89},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x8F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x8A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x91},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x8A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x89},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x2C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x76},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xF1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x6E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x9D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xE9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x20},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x64},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402ef7c0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x71},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xA7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xB1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x2F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xD6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x80},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x5A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xBB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x39},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x49},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x88},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xEB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x42},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xD5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xDB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x85},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x6E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xEE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x35},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xA1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x44},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xF4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xD9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x3A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x84},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x27},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x49},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xBE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x14},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402f2780(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::xor_value, 0xC, ByteOperation::reverse_subtract, 0x48, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x23},
                ByteFormula{ByteOperation::add, 0x78, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::xor_value, 0x29, ByteOperation::add, 0xDB, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x46},
                ByteFormula{ByteOperation::xor_value, 0xB7, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0xC5},
                ByteFormula{ByteOperation::xor_value, 0xC0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0x10},
                ByteFormula{ByteOperation::xor_value, 0x20, ByteOperation::add, 0xD4, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::xor_value, 0xA6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0xD5},
                ByteFormula{ByteOperation::xor_value, 0xB7, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0x92},
                ByteFormula{ByteOperation::xor_value, 0x3B, ByteOperation::reverse_subtract, 0xAF, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::xor_value, 0x24, ByteOperation::add, 0xCF, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD},
                ByteFormula{ByteOperation::xor_value, 0x1F, ByteOperation::reverse_subtract, 0x11, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF},
                ByteFormula{ByteOperation::xor_value, 0x3D, ByteOperation::reverse_subtract, 0xC0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x41},
                ByteFormula{ByteOperation::xor_value, 0x35, ByteOperation::add, 0x87, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::xor_value, 0xF, ByteOperation::add, 0x3E, ByteOperation::identity, 0x0, 7, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x76},
                ByteFormula{ByteOperation::xor_value, 0x8, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::add, 0x7},
                ByteFormula{ByteOperation::xor_value, 0x26, ByteOperation::reverse_subtract, 0x2A, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x36},
                ByteFormula{ByteOperation::xor_value, 0x2D, ByteOperation::add, 0x5E, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x3},
                ByteFormula{ByteOperation::xor_value, 0x1E, ByteOperation::reverse_subtract, 0x17, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::xor_value, 0x95, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0xCC},
                ByteFormula{ByteOperation::xor_value, 0x1D, ByteOperation::reverse_subtract, 0x11, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::xor_value, 0x9F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::add, 0x6A},
                ByteFormula{ByteOperation::xor_value, 0x38, ByteOperation::reverse_subtract, 0x33, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x28},
                ByteFormula{ByteOperation::xor_value, 0x6F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0xFD},
                ByteFormula{ByteOperation::xor_value, 0x37, ByteOperation::reverse_subtract, 0xBA, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x27},
                ByteFormula{ByteOperation::xor_value, 0xA4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x77},
                ByteFormula{ByteOperation::xor_value, 0x32, ByteOperation::reverse_subtract, 0x2E, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x22},
                ByteFormula{ByteOperation::xor_value, 0x9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x41},
                ByteFormula{ByteOperation::xor_value, 0x1B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0xA4},
                ByteFormula{ByteOperation::xor_value, 0xBA, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x63},
                ByteFormula{ByteOperation::xor_value, 0x11, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::add, 0x51},
                ByteFormula{ByteOperation::xor_value, 0x15, ByteOperation::reverse_subtract, 0x98, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::xor_value, 0x11, ByteOperation::reverse_subtract, 0x9B, ByteOperation::identity, 0x0, 1, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::xor_value, 0x62, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0xE0},
                ByteFormula{ByteOperation::xor_value, 0x4, ByteOperation::reverse_subtract, 0x9, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x14},
                ByteFormula{ByteOperation::xor_value, 0x3D, ByteOperation::reverse_subtract, 0x33, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x28},
                ByteFormula{ByteOperation::xor_value, 0x62, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0xEA},
                ByteFormula{ByteOperation::xor_value, 0x62, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x35},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402f50c0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x64},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xB9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x86},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xAD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xBC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x83},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x92},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402f7360(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xEA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xCD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xEF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x5E},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402f8f40(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x1B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xFB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xF3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xEB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xF3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1B},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1402fb9a0(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::xor_value, 0x4D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::add, 0x5E},
                ByteFormula{ByteOperation::xor_value, 0x38, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::add, 0x6D},
                ByteFormula{ByteOperation::xor_value, 0xA4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::add, 0xC0},
                ByteFormula{ByteOperation::xor_value, 0x2F, ByteOperation::reverse_subtract, 0x33, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::xor_value, 0x26, ByteOperation::add, 0x81, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x5},
                ByteFormula{ByteOperation::xor_value, 0x8C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::add, 0x49},
                ByteFormula{ByteOperation::xor_value, 0xC0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::add, 0x12},
                ByteFormula{ByteOperation::xor_value, 0x7C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::add, 0x88},
                ByteFormula{ByteOperation::xor_value, 0xB9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x55},
                ByteFormula{ByteOperation::xor_value, 0x35, ByteOperation::add, 0xD3, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x36},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140302a80(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x90},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xAF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x81},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x18},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x50},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xD4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB7},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1403087e0(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xB4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xD8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x3C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x42},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xEA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x8D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x5E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x8B},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14030af00(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x3D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xEF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x5B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x1F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x94},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14030c940(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x6D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::add, 0x27, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x22},
                ByteFormula{ByteOperation::add, 0x76, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x71},
                ByteFormula{ByteOperation::add, 0x19, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::add, 0x29, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x58},
                ByteFormula{ByteOperation::add, 0x7A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xF5},
                ByteFormula{ByteOperation::add, 0x9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::add, 0x37, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::add, 0x1F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xF7},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14030fd80(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::xor_value, 0x2B, ByteOperation::reverse_subtract, 0x83, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2},
                ByteFormula{ByteOperation::xor_value, 0x22, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::add, 0x19},
                ByteFormula{ByteOperation::xor_value, 0x34, ByteOperation::add, 0x62, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x40},
                ByteFormula{ByteOperation::xor_value, 0x29, ByteOperation::add, 0x6D, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x22},
                ByteFormula{ByteOperation::xor_value, 0x2B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x6E},
                ByteFormula{ByteOperation::xor_value, 0xF0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x3D},
                ByteFormula{ByteOperation::xor_value, 0x29, ByteOperation::reverse_subtract, 0xA2, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::xor_value, 0x12, ByteOperation::add, 0xE6, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x4C},
                ByteFormula{ByteOperation::xor_value, 0x20, ByteOperation::add, 0xF5, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x5C},
                ByteFormula{ByteOperation::xor_value, 0x62, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0xC2},
                ByteFormula{ByteOperation::xor_value, 0xBB, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::add, 0x83},
                ByteFormula{ByteOperation::xor_value, 0x2E, ByteOperation::add, 0x7A, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x50},
                ByteFormula{ByteOperation::xor_value, 0x16, ByteOperation::reverse_subtract, 0x3D, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::xor_value, 0x2D, ByteOperation::reverse_subtract, 0x86, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x2C},
                ByteFormula{ByteOperation::xor_value, 0x22, ByteOperation::reverse_subtract, 0xC7, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x60},
                ByteFormula{ByteOperation::xor_value, 0x74, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::add, 0xE5},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140313660(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::xor_value, 0x31, ByteOperation::reverse_subtract, 0x74, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::add, 0x3A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x30},
                ByteFormula{ByteOperation::xor_value, 0x2B, ByteOperation::add, 0x19, ByteOperation::identity, 0x0, 2, ByteOperation::identity, 0x0},
                ByteFormula{ByteOperation::xor_value, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0xBF},
                ByteFormula{ByteOperation::xor_value, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x76},
                ByteFormula{ByteOperation::xor_value, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x25},
                ByteFormula{ByteOperation::xor_value, 0x2F, ByteOperation::add, 0x94, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::xor_value, 0x1B, ByteOperation::reverse_subtract, 0xCE, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x1E},
                ByteFormula{ByteOperation::xor_value, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x39},
                ByteFormula{ByteOperation::xor_value, 0x26, ByteOperation::reverse_subtract, 0xE2, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x2B},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140316d00(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x3F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x42},
                ByteFormula{ByteOperation::add, 0x10, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x86},
                ByteFormula{ByteOperation::add, 0xE, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8E},
                ByteFormula{ByteOperation::add, 0x61, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x3B},
                ByteFormula{ByteOperation::add, 0x7B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x53},
                ByteFormula{ByteOperation::add, 0x7B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xA6},
                ByteFormula{ByteOperation::add, 0x71, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xF6},
                ByteFormula{ByteOperation::add, 0x65, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x2B},
                ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x46},
                ByteFormula{ByteOperation::add, 0x8, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::add, 0x16, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x77},
                ByteFormula{ByteOperation::add, 0x6A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::add, 0x1, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x5D},
                ByteFormula{ByteOperation::add, 0x15, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::add, 0x5C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xF5},
                ByteFormula{ByteOperation::add, 0x23, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x8C},
                ByteFormula{ByteOperation::add, 0x7E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::add, 0x9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xA6},
                ByteFormula{ByteOperation::add, 0x70, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xC1},
                ByteFormula{ByteOperation::add, 0x3F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x90},
                ByteFormula{ByteOperation::add, 0x6A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xC7},
                ByteFormula{ByteOperation::add, 0x1D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xB2},
                ByteFormula{ByteOperation::add, 0x34, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x9D},
                ByteFormula{ByteOperation::add, 0x2C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::add, 0x43, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x76},
                ByteFormula{ByteOperation::add, 0x4, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD6},
                ByteFormula{ByteOperation::add, 0x49, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::add, 0x36, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCD},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140319000(const char* source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x13},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x2A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x16},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14031cdd0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x46, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x75},
                ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x8B},
                ByteFormula{ByteOperation::add, 0x28, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x44},
                ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xB5},
                ByteFormula{ByteOperation::xor_value, 0x7E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x2E},
                ByteFormula{ByteOperation::add, 0x1, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAF},
                ByteFormula{ByteOperation::add, 0x5B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x5F},
                ByteFormula{ByteOperation::add, 0x20, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::add, 0x4D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x28},
                ByteFormula{ByteOperation::add, 0x3F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::add, 0x44, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xCE},
                ByteFormula{ByteOperation::add, 0x2C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x42},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14031f280(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x37},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x5B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x31},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x25},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14032c290(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x45},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xFE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xF1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x5D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x91},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x32},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x67},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x3D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x9D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x83},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xA1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x83},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x85},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x86},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xE3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xDF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x26},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x1},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14032e280(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x6D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x71},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xD4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA9},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14032f7c0(const std::byte* source) {
    static constexpr std::array schedule{
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x55},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x35},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD1},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD4},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD4},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x2D},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x29},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD4},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x6A},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xD5},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x51},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x49},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x6A},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xB1},
        ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x2D},
    };
    return decode_bytes(source, schedule);
}


std::byte* decode_protected_bytes_140332c00(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xF2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x91},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x91},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x2E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x34},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x23},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x23},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140334600(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::add, 0x2, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x27},
                ByteFormula{ByteOperation::add, 0x53, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x74},
                ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x4},
                ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::add, 0x26, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x3},
                ByteFormula{ByteOperation::xor_value, 0x9, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x30},
                ByteFormula{ByteOperation::add, 0x34, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::add, 0x61, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::add, 0x2, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE4},
                ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE9},
                ByteFormula{ByteOperation::add, 0x37, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x80},
                ByteFormula{ByteOperation::add, 0xF, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x41},
                ByteFormula{ByteOperation::add, 0x13, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x86},
                ByteFormula{ByteOperation::add, 0x5E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x6F},
                ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x40},
                ByteFormula{ByteOperation::add, 0x23, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::add, 0x58, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC5},
                ByteFormula{ByteOperation::add, 0x39, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::add, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x58},
                ByteFormula{ByteOperation::add, 0x68, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x5},
                ByteFormula{ByteOperation::add, 0x13, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::add, 0x65, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x90},
                ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::add, 0x4D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::add, 0xE, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x65},
                ByteFormula{ByteOperation::add, 0x47, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::add, 0x63, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x22},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1403370e0(const std::byte* source) {
    const auto* input = source;
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::add, 0x6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCF},
                ByteFormula{ByteOperation::add, 0x57, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x66},
                ByteFormula{ByteOperation::add, 0x3C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD0},
                ByteFormula{ByteOperation::add, 0x16, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x1F},
                ByteFormula{ByteOperation::add, 0x45, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xBD},
                ByteFormula{ByteOperation::add, 0x2C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xD8},
                ByteFormula{ByteOperation::add, 0xC, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x23},
                ByteFormula{ByteOperation::add, 0x59, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::add, 0x3A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8E},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140339d00(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x91},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x38},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xF8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xF7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x31},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xEA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xDF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x85},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x49},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x32},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x68},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xC4},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x5D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xD5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x64},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xCE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x75},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x13},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x19},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x9E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x20},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x6E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x70},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x8A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x46},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x4C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xF2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xDA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x13},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xE3},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14033c240(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x7A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x46},
                ByteFormula{ByteOperation::add, 0x49, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x60},
                ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::add, 0x43, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x84},
                ByteFormula{ByteOperation::add, 0xA, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x21},
                ByteFormula{ByteOperation::add, 0x6D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE4},
                ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA5},
                ByteFormula{ByteOperation::add, 0x18, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x2E},
                ByteFormula{ByteOperation::add, 0x45, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::add, 0x26, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6E},
                ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x2D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xB4},
                ByteFormula{ByteOperation::add, 0x48, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::add, 0x37, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x7D},
                ByteFormula{ByteOperation::add, 0x4E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6},
                ByteFormula{ByteOperation::add, 0x1, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x4B},
                ByteFormula{ByteOperation::xor_value, 0x14, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::add, 0x60},
                ByteFormula{ByteOperation::add, 0x2B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::add, 0x1D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::add, 0x4E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xC},
                ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::add, 0x70, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x48},
                ByteFormula{ByteOperation::add, 0x41, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::add, 0x3E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD9},
                ByteFormula{ByteOperation::add, 0x6, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x39},
                ByteFormula{ByteOperation::add, 0x71, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::add, 0x3C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC1},
                ByteFormula{ByteOperation::add, 0x73, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xE4},
                ByteFormula{ByteOperation::add, 0x26, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xB9},
                ByteFormula{ByteOperation::add, 0x51, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x6C},
                ByteFormula{ByteOperation::add, 0x63, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xA4},
                ByteFormula{ByteOperation::add, 0x28, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xD8},
                ByteFormula{ByteOperation::add, 0x69, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8C},
                ByteFormula{ByteOperation::add, 0x5A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x90},
                ByteFormula{ByteOperation::add, 0x3, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x4A},
                ByteFormula{ByteOperation::add, 0x39, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x9B},
                ByteFormula{ByteOperation::add, 0x5C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x20},
                ByteFormula{ByteOperation::add, 0x33, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::add, 0x7A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x64},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14033e500(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xC0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xCF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x47},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xDF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x9A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xEC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xE7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xB3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x50},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x7F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xB3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x65},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x1F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x4C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x95},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x5C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x5C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x6B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xBD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x17},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x29},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x32},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x87},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xCA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x51},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x8C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x7B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x10},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140341b00(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xD3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x45},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xB3},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x40},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xEF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xDF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x15},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x15},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x37},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x8C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xA1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x1A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x89},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x49},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x92},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xB6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x75},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xFE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xBF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x9D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x40},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x7C},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_1403443f0(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x65},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x5A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x8B},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x3F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x95},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x99},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xC6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x56},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xA6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x12},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xAC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x81},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xB8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x8E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xBD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x74},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xA9},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x21},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x77},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x5A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xB1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xAC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x72},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xD1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x7B},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140346500(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x1C},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x17},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xB0},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x6A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xFD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x61},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x4F},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7A},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xC8},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xF5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xA7},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x14},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xAD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xCA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x1},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x95},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x16},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x61},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x57},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x21},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xAD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xED},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xED},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xD5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x74},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x60},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_140349a40(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::add, 0x2, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xB1},
                ByteFormula{ByteOperation::add, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFD},
                ByteFormula{ByteOperation::add, 0x64, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x94},
                ByteFormula{ByteOperation::add, 0xF, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x39},
                ByteFormula{ByteOperation::add, 0x7E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::add, 0x15, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7A},
                ByteFormula{ByteOperation::add, 0x1F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x3B},
                ByteFormula{ByteOperation::add, 0x64, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0x29},
                ByteFormula{ByteOperation::add, 0x31, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 6, ByteOperation::xor_value, 0xFD},
                ByteFormula{ByteOperation::add, 0x52, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x4B},
                ByteFormula{ByteOperation::add, 0x2B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xDE},
                ByteFormula{ByteOperation::add, 0x40, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x7C},
                ByteFormula{ByteOperation::add, 0x8, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x60},
                ByteFormula{ByteOperation::add, 0x43, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xC2},
                ByteFormula{ByteOperation::add, 0x36, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x2F},
                ByteFormula{ByteOperation::add, 0x4D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xB8},
                ByteFormula{ByteOperation::add, 0x14, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x4D},
                ByteFormula{ByteOperation::add, 0x5F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x99},
                ByteFormula{ByteOperation::add, 0x51, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0xBC},
                ByteFormula{ByteOperation::add, 0x2, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x36},
                ByteFormula{ByteOperation::add, 0x6F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x9A},
                ByteFormula{ByteOperation::add, 0x24, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x27},
                ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x3F},
                ByteFormula{ByteOperation::add, 0x46, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x14},
                ByteFormula{ByteOperation::add, 0x46, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x28},
                ByteFormula{ByteOperation::add, 0x5, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x78},
                ByteFormula{ByteOperation::add, 0x50, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x11},
                ByteFormula{ByteOperation::add, 0xB, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x37},
                ByteFormula{ByteOperation::add, 0x6A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xBA},
                ByteFormula{ByteOperation::add, 0x11, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xFA},
                ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x77},
                ByteFormula{ByteOperation::add, 0x60, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x62},
                ByteFormula{ByteOperation::add, 0x1D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x7B},
                ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAB},
                ByteFormula{ByteOperation::add, 0x77, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xC6},
                ByteFormula{ByteOperation::add, 0x4D, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x2E},
                ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::add, 0x7F, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x73},
                ByteFormula{ByteOperation::add, 0x3A, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xFB},
                ByteFormula{ByteOperation::add, 0x71, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x6F},
                ByteFormula{ByteOperation::add, 0x18, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x43},
                ByteFormula{ByteOperation::add, 0x14, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xA9},
                ByteFormula{ByteOperation::add, 0x45, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x83},
                ByteFormula{ByteOperation::add, 0x26, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 3, ByteOperation::xor_value, 0x17},
            };
    return decode_bytes(input, schedule);
}


std::byte* decode_protected_bytes_14034c180(std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
            static constexpr std::array schedule{
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x56},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xA5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0x10},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xDB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 0, ByteOperation::xor_value, 0xAA},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x36},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x94},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x7D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xCD},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xB6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x77},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xA6},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0x76},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0xDC},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x43},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 7, ByteOperation::xor_value, 0xFF},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x9D},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x48},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 4, ByteOperation::xor_value, 0x97},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0xAE},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0x17},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xE2},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 5, ByteOperation::xor_value, 0xCB},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 2, ByteOperation::xor_value, 0x86},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x3E},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0xF5},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x79},
                ByteFormula{ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, ByteOperation::identity, 0x0, 1, ByteOperation::xor_value, 0x1B},
            };
    return decode_bytes(input, schedule);
}

}
