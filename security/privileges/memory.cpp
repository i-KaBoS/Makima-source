#include "security/privileges/privileges.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <cstring>
#include <span>

#include "../../payload/crypto/crypto.hpp"
#include "digest.hpp"

namespace makima::security::privileges {

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

std::uint8_t rotate_byte_left(std::uint8_t value, unsigned count) noexcept {
    count &= 7U;
    if (count == 0) return value;
    return static_cast<std::uint8_t>(
        (value << count) | (value >> (8U - count)));
}

template <std::size_t Size>
std::byte* decode_privilege_bytes(
    const std::byte* source,
    const std::array<ByteFormula, Size>& schedule) {
    auto* output = static_cast<std::byte*>(::operator new(Size + 1U));
    for (std::size_t index = 0; index < Size; ++index) {
        const auto input = std::to_integer<std::uint8_t>(source[index]);
        const auto& formula = schedule[index];
        auto value = apply_byte_operation(
            input, formula.first_operation, formula.first_key);
        value = apply_byte_operation(
            value, formula.second_operation, formula.second_key);
        value = rotate_byte_left(value, formula.rotation_count);
        value = apply_byte_operation(
            value, formula.final_operation, formula.final_key);
        output[index] = static_cast<std::byte>(value);
    }
    output[Size] = std::byte{};
    return output;
}


std::byte* decode_protected_privilege_bytes_14034f880(const std::byte* source) {
    static constexpr std::array<ByteFormula, 49> schedule{{
        ByteFormula{ByteOperation::add, 0x11, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x93},
        ByteFormula{ByteOperation::add, 0x22, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xB5},
        ByteFormula{ByteOperation::add, 0x73, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xDF},
        ByteFormula{ByteOperation::add, 0x6D, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x70},
        ByteFormula{ByteOperation::add, 0x55, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x1B},
        ByteFormula{ByteOperation::add, 0x77, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x7D},
        ByteFormula{ByteOperation::add, 0x10, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x70},
        ByteFormula{ByteOperation::add, 0x4B, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xD8},
        ByteFormula{ByteOperation::add, 0x6B, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xE6},
        ByteFormula{ByteOperation::add, 0x79, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::add, 0x49, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xC4},
        ByteFormula{ByteOperation::add, 0x66, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xE9},
        ByteFormula{ByteOperation::add, 0x2F, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x8A},
        ByteFormula{ByteOperation::add, 0x6C, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x9F},
        ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xA2},
        ByteFormula{ByteOperation::add, 0x2F, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xA2},
        ByteFormula{ByteOperation::add, 0x72, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xFB},
        ByteFormula{ByteOperation::add, 0x78, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xDF},
        ByteFormula{ByteOperation::add, 0x33, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x7D},
        ByteFormula{ByteOperation::add, 0x64, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xDF},
        ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x71},
        ByteFormula{ByteOperation::add, 0x33, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xF5},
        ByteFormula{ByteOperation::add, 0x1E, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x8C},
        ByteFormula{ByteOperation::add, 0x55, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xC6},
        ByteFormula{ByteOperation::add, 0x6D, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xE0},
        ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xA1},
        ByteFormula{ByteOperation::add, 0x67, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xEA},
        ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x97},
        ByteFormula{ByteOperation::add, 0x79, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xF4},
        ByteFormula{ByteOperation::add, 0x3A, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xB5},
        ByteFormula{ByteOperation::add, 0x0C, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x87},
        ByteFormula{ByteOperation::add, 0x3E, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xC6},
        ByteFormula{ByteOperation::add, 0x47, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x56},
        ByteFormula{ByteOperation::add, 0x78, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xDF},
        ByteFormula{ByteOperation::add, 0x60, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xA7},
        ByteFormula{ByteOperation::add, 0x66, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::add, 0x33, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x7D},
        ByteFormula{ByteOperation::add, 0x1D, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x84},
        ByteFormula{ByteOperation::add, 0x64, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x7F},
        ByteFormula{ByteOperation::add, 0x13, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xF4},
        ByteFormula{ByteOperation::add, 0x3F, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xAC},
        ByteFormula{ByteOperation::add, 0x03, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xA3},
        ByteFormula{ByteOperation::add, 0x56, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x76},
        ByteFormula{ByteOperation::add, 0x0D, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x20},
        ByteFormula{ByteOperation::add, 0x79, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x4F},
        ByteFormula{ByteOperation::add, 0x36, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x9B},
        ByteFormula{ByteOperation::add, 0x1A, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x65},
        ByteFormula{ByteOperation::add, 0x3C, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xED},
        ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xF2},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_140351f00(const std::byte* source) {
    static constexpr std::array<ByteFormula, 38> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xA4},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xE5},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xC8},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xCD},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xF1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xE5},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x26},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x4C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xDC},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x1A},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x85},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xC7},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x5E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x98},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x2C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x54},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x97},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xCD},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xBA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xBA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xBA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xCD},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xBA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x38},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x64},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xE3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xC7},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x04},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x0E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x08},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x32},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x97},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xB0},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x8C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x76},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403539a0(const std::byte* source) {
    static constexpr std::array<ByteFormula, 17> schedule{{
        ByteFormula{ByteOperation::add, 0x06, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x6A},
        ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xE3},
        ByteFormula{ByteOperation::add, 0x68, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x79},
        ByteFormula{ByteOperation::add, 0x3E, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x75},
        ByteFormula{ByteOperation::add, 0x77, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x3E},
        ByteFormula{ByteOperation::add, 0x11, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x0B},
        ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x4A},
        ByteFormula{ByteOperation::add, 0x69, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x20},
        ByteFormula{ByteOperation::add, 0x0D, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x88},
        ByteFormula{ByteOperation::add, 0x6E, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xA4},
        ByteFormula{ByteOperation::add, 0x2F, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xCC},
        ByteFormula{ByteOperation::add, 0x35, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x3E},
        ByteFormula{ByteOperation::add, 0x0D, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x22},
        ByteFormula{ByteOperation::add, 0x4A, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x80},
        ByteFormula{ByteOperation::add, 0x07, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x27},
        ByteFormula{ByteOperation::add, 0x49, ByteOperation::identity, 0x00, 6, ByteOperation::identity, 0x00},
        ByteFormula{ByteOperation::add, 0x21, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x34},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403574a0(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::add, 0x08, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xB9},
        ByteFormula{ByteOperation::add, 0x21, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x29},
        ByteFormula{ByteOperation::add, 0x66, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x18},
        ByteFormula{ByteOperation::add, 0x09, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xC2},
        ByteFormula{ByteOperation::add, 0x44, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x54},
        ByteFormula{ByteOperation::add, 0x05, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x5B},
        ByteFormula{ByteOperation::add, 0x19, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xE2},
        ByteFormula{ByteOperation::add, 0x4C, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x88},
        ByteFormula{ByteOperation::add, 0x0F, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xCE},
        ByteFormula{ByteOperation::add, 0x7A, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x04},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_140366a40(const std::byte* source) {
    static constexpr std::array<ByteFormula, 16> schedule{{
        ByteFormula{ByteOperation::xor_value, 0x59, ByteOperation::identity, 0x00, 6, ByteOperation::reverse_subtract, 0x80},
        ByteFormula{ByteOperation::xor_value, 0x30, ByteOperation::add, 0x38, 5, ByteOperation::xor_value, 0xEE},
        ByteFormula{ByteOperation::xor_value, 0x1D, ByteOperation::add, 0x15, 6, ByteOperation::xor_value, 0xE2},
        ByteFormula{ByteOperation::xor_value, 0x0E, ByteOperation::add, 0x06, 6, ByteOperation::xor_value, 0x30},
        ByteFormula{ByteOperation::xor_value, 0x1D, ByteOperation::identity, 0x00, 1, ByteOperation::reverse_subtract, 0x44},
        ByteFormula{ByteOperation::xor_value, 0x14, ByteOperation::add, 0x1C, 6, ByteOperation::xor_value, 0xAA},
        ByteFormula{ByteOperation::xor_value, 0x2B, ByteOperation::identity, 0x00, 1, ByteOperation::reverse_subtract, 0x9F},
        ByteFormula{ByteOperation::xor_value, 0x25, ByteOperation::add, 0x2D, 6, ByteOperation::xor_value, 0xDA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xB4},
        ByteFormula{ByteOperation::xor_value, 0x17, ByteOperation::add, 0x1F, 6, ByteOperation::xor_value, 0x68},
        ByteFormula{ByteOperation::xor_value, 0x09, ByteOperation::identity, 0x00, 0, ByteOperation::add, 0xAC},
        ByteFormula{ByteOperation::xor_value, 0x06, ByteOperation::add, 0x0F, 7, ByteOperation::xor_value, 0xF9},
        ByteFormula{ByteOperation::xor_value, 0x09, ByteOperation::identity, 0x00, 0, ByteOperation::add, 0xBF},
        ByteFormula{ByteOperation::xor_value, 0x09, ByteOperation::identity, 0x00, 0, ByteOperation::add, 0x7C},
        ByteFormula{ByteOperation::xor_value, 0x09, ByteOperation::identity, 0x00, 0, ByteOperation::add, 0x35},
        ByteFormula{ByteOperation::xor_value, 0x09, ByteOperation::identity, 0x00, 0, ByteOperation::add, 0xCE},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_14036a240(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x2E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xA3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x3D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x56},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x08},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x82},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xAB},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xFC},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x5B},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x39},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403dbb60(const std::byte* source) {
    static constexpr std::array<ByteFormula, 16> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x40},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xC1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x79},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xB8},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x43},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x1E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x8C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xED},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x95},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x94},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xB1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x75},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xCD},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x9D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x14},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x4B},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403de900(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x8C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x13},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xDF},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x9E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x2A},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xD3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x86},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x61},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x5B},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x8A},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403e1e00(const std::byte* source) {
    static constexpr std::array<ByteFormula, 14> schedule{{
        ByteFormula{ByteOperation::add, 0x4D, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xF0},
        ByteFormula{ByteOperation::add, 0x3F, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x28},
        ByteFormula{ByteOperation::add, 0x6E, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x1D},
        ByteFormula{ByteOperation::add, 0x01, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xCB},
        ByteFormula{ByteOperation::add, 0x09, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x5A},
        ByteFormula{ByteOperation::add, 0x1B, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xD4},
        ByteFormula{ByteOperation::add, 0x54, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xF7},
        ByteFormula{ByteOperation::add, 0x56, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x3D},
        ByteFormula{ByteOperation::add, 0x07, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x57},
        ByteFormula{ByteOperation::add, 0x68, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x7B},
        ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x13},
        ByteFormula{ByteOperation::add, 0x4B, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xBD},
        ByteFormula{ByteOperation::add, 0x32, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x63},
        ByteFormula{ByteOperation::add, 0x38, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xE2},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403e4a80(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xDA},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xB3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xA1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xA1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x70},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x0B},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x4A},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x3D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x94},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xD9},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403e7000(const std::byte* source) {
    static constexpr std::array<ByteFormula, 16> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x59},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xC9},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xD0},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xF6},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x3D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x0F},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x29},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x6C},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xBF},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xD2},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xFC},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xB0},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x04},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xC1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::identity, 0x00},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x72},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403ea4e0(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x43},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xD6},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x07},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xBC},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x64},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xBF},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x6D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x02},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x4F},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x25},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403ece70(const std::byte* source) {
    static constexpr std::array<ByteFormula, 17> schedule{{
        ByteFormula{ByteOperation::add, 0x6D, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x1E},
        ByteFormula{ByteOperation::add, 0x0E, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x2A},
        ByteFormula{ByteOperation::add, 0x5F, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x1F},
        ByteFormula{ByteOperation::add, 0x34, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xC9},
        ByteFormula{ByteOperation::add, 0x79, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x7D},
        ByteFormula{ByteOperation::add, 0x2A, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x68},
        ByteFormula{ByteOperation::add, 0x24, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xC8},
        ByteFormula{ByteOperation::add, 0x37, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x66},
        ByteFormula{ByteOperation::add, 0x36, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x53},
        ByteFormula{ByteOperation::add, 0x55, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x7F},
        ByteFormula{ByteOperation::add, 0x48, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x3A},
        ByteFormula{ByteOperation::add, 0x3B, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xB2},
        ByteFormula{ByteOperation::add, 0x03, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xB5},
        ByteFormula{ByteOperation::add, 0x18, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x17},
        ByteFormula{ByteOperation::add, 0x09, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xF4},
        ByteFormula{ByteOperation::add, 0x72, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x7B},
        ByteFormula{ByteOperation::add, 0x2F, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x06},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403ef400(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0x39},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xE4},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x0F},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 6, ByteOperation::xor_value, 0xF5},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x65},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x78},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xA6},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xC6},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xB2},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xEE},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403f7c00(const std::byte* source) {
    static constexpr std::array<ByteFormula, 16> schedule{{
        ByteFormula{ByteOperation::xor_value, 0x0A, ByteOperation::add, 0x4B, 6, ByteOperation::xor_value, 0xCE},
        ByteFormula{ByteOperation::xor_value, 0x38, ByteOperation::add, 0x7C, 6, ByteOperation::xor_value, 0xBF},
        ByteFormula{ByteOperation::xor_value, 0x66, ByteOperation::identity, 0x00, 3, ByteOperation::add, 0x98},
        ByteFormula{ByteOperation::xor_value, 0x04, ByteOperation::add, 0x46, 6, ByteOperation::xor_value, 0x81},
        ByteFormula{ByteOperation::xor_value, 0x04, ByteOperation::identity, 0x00, 3, ByteOperation::add, 0xB2},
        ByteFormula{ByteOperation::xor_value, 0x71, ByteOperation::identity, 0x00, 4, ByteOperation::add, 0x61},
        ByteFormula{ByteOperation::xor_value, 0x14, ByteOperation::add, 0x56, 6, ByteOperation::xor_value, 0x91},
        ByteFormula{ByteOperation::xor_value, 0x42, ByteOperation::identity, 0x00, 4, ByteOperation::add, 0xB0},
        ByteFormula{ByteOperation::add, 0x44, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x7B},
        ByteFormula{ByteOperation::xor_value, 0x24, ByteOperation::identity, 0x00, 4, ByteOperation::reverse_subtract, 0x1D},
        ByteFormula{ByteOperation::xor_value, 0x24, ByteOperation::identity, 0x00, 4, ByteOperation::add, 0xDF},
        ByteFormula{ByteOperation::xor_value, 0x0C, ByteOperation::add, 0x4D, 3, ByteOperation::xor_value, 0x6C},
        ByteFormula{ByteOperation::xor_value, 0x60, ByteOperation::identity, 0x00, 4, ByteOperation::add, 0xCC},
        ByteFormula{ByteOperation::xor_value, 0x0E, ByteOperation::add, 0x4E, 3, ByteOperation::xor_value, 0xEE},
        ByteFormula{ByteOperation::xor_value, 0x52, ByteOperation::identity, 0x00, 5, ByteOperation::add, 0xC2},
        ByteFormula{ByteOperation::xor_value, 0x60, ByteOperation::identity, 0x00, 5, ByteOperation::add, 0xB9},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_1403fb0f0(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xA3},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x1E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x53},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x55},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xC0},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x1B},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xDE},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0xED},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0xE7},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 4, ByteOperation::xor_value, 0x47},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_140401760(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::xor_value, 0x08, ByteOperation::add, 0x58, 2, ByteOperation::xor_value, 0xAC},
        ByteFormula{ByteOperation::xor_value, 0x2E, ByteOperation::identity, 0x00, 7, ByteOperation::add, 0xC7},
        ByteFormula{ByteOperation::xor_value, 0x5A, ByteOperation::identity, 0x00, 7, ByteOperation::add, 0x16},
        ByteFormula{ByteOperation::xor_value, 0x07, ByteOperation::add, 0x59, 2, ByteOperation::xor_value, 0xA3},
        ByteFormula{ByteOperation::xor_value, 0x30, ByteOperation::add, 0x6C, 2, ByteOperation::xor_value, 0x9B},
        ByteFormula{ByteOperation::xor_value, 0x42, ByteOperation::identity, 0x00, 7, ByteOperation::add, 0xE3},
        ByteFormula{ByteOperation::xor_value, 0x17, ByteOperation::add, 0x49, 2, ByteOperation::xor_value, 0xB3},
        ByteFormula{ByteOperation::xor_value, 0x26, ByteOperation::identity, 0x00, 4, ByteOperation::reverse_subtract, 0xAD},
        ByteFormula{ByteOperation::xor_value, 0x01, ByteOperation::add, 0x5F, 1, ByteOperation::xor_value, 0x25},
        ByteFormula{ByteOperation::xor_value, 0x40, ByteOperation::identity, 0x00, 4, ByteOperation::add, 0x20},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_140404d00(const std::byte* source) {
    static constexpr std::array<ByteFormula, 16> schedule{{
        ByteFormula{ByteOperation::add, 0x2E, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xD4},
        ByteFormula{ByteOperation::add, 0x1D, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x4C},
        ByteFormula{ByteOperation::add, 0x50, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xE5},
        ByteFormula{ByteOperation::add, 0x23, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x53},
        ByteFormula{ByteOperation::add, 0x6A, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0xF6},
        ByteFormula{ByteOperation::add, 0x44, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x3E},
        ByteFormula{ByteOperation::add, 0x33, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x5B},
        ByteFormula{ByteOperation::add, 0x0D, ByteOperation::identity, 0x00, 3, ByteOperation::xor_value, 0x44},
        ByteFormula{ByteOperation::add, 0x25, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xA0},
        ByteFormula{ByteOperation::add, 0x46, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xC1},
        ByteFormula{ByteOperation::add, 0x7E, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xE7},
        ByteFormula{ByteOperation::add, 0x51, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x53},
        ByteFormula{ByteOperation::add, 0x69, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0xB3},
        ByteFormula{ByteOperation::add, 0x57, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xD2},
        ByteFormula{ByteOperation::add, 0x1A, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x9D},
        ByteFormula{ByteOperation::add, 0x1C, ByteOperation::identity, 0x00, 2, ByteOperation::xor_value, 0x7E},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_140408300(const std::byte* source) {
    static constexpr std::array<ByteFormula, 10> schedule{{
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x44},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0x67},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x26},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xD1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 5, ByteOperation::xor_value, 0xCD},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0xD1},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0x0D},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x1E},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 0, ByteOperation::xor_value, 0x73},
        ByteFormula{ByteOperation::identity, 0x00, ByteOperation::identity, 0x00, 1, ByteOperation::xor_value, 0xE2},
    }};
    return decode_privilege_bytes(source, schedule);
}


std::byte* decode_protected_privilege_bytes_14040a3f0(const std::byte* source) {
    static constexpr std::array<ByteFormula, 17> schedule{{
        ByteFormula{ByteOperation::xor_value, 0x26, ByteOperation::add, 0x0A, 0, ByteOperation::xor_value, 0x2B},
        ByteFormula{ByteOperation::xor_value, 0x17, ByteOperation::add, 0x3B, 7, ByteOperation::xor_value, 0x9A},
        ByteFormula{ByteOperation::xor_value, 0x38, ByteOperation::add, 0x18, 7, ByteOperation::xor_value, 0x37},
        ByteFormula{ByteOperation::xor_value, 0x19, ByteOperation::identity, 0x00, 1, ByteOperation::add, 0xAA},
        ByteFormula{ByteOperation::xor_value, 0x1C, ByteOperation::add, 0x32, 7, ByteOperation::xor_value, 0x90},
        ByteFormula{ByteOperation::xor_value, 0x33, ByteOperation::add, 0x1F, 7, ByteOperation::xor_value, 0xBE},
        ByteFormula{ByteOperation::xor_value, 0x39, ByteOperation::add, 0x15, 7, ByteOperation::xor_value, 0x34},
        ByteFormula{ByteOperation::add, 0x30, ByteOperation::identity, 0x00, 7, ByteOperation::xor_value, 0x0F},
        ByteFormula{ByteOperation::xor_value, 0x23, ByteOperation::identity, 0x00, 1, ByteOperation::reverse_subtract, 0x2F},
        ByteFormula{ByteOperation::xor_value, 0x5B, ByteOperation::identity, 0x00, 2, ByteOperation::reverse_subtract, 0x4E},
        ByteFormula{ByteOperation::xor_value, 0x48, ByteOperation::identity, 0x00, 2, ByteOperation::reverse_subtract, 0x0D},
        ByteFormula{ByteOperation::xor_value, 0x20, ByteOperation::add, 0x0C, 2, ByteOperation::xor_value, 0xAD},
        ByteFormula{ByteOperation::xor_value, 0x18, ByteOperation::identity, 0x00, 2, ByteOperation::reverse_subtract, 0x18},
        ByteFormula{ByteOperation::xor_value, 0x53, ByteOperation::identity, 0x00, 2, ByteOperation::add, 0xDE},
        ByteFormula{ByteOperation::xor_value, 0x12, ByteOperation::add, 0x3E, 2, ByteOperation::xor_value, 0x9F},
        ByteFormula{ByteOperation::xor_value, 0x48, ByteOperation::identity, 0x00, 2, ByteOperation::add, 0x6C},
        ByteFormula{ByteOperation::xor_value, 0x1F, ByteOperation::identity, 0x00, 2, ByteOperation::reverse_subtract, 0xB4},
    }};
    return decode_privilege_bytes(source, schedule);
}



char* allocate_algorithm_context_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[15] = "%s\n%s\n%s\n%s\n%s";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



[[maybe_unused]] char* allocate_unsigned_decimal_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[5] = "%llu";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

}




wchar_t* allocate_process_target_truncate_mode(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"TRUNCATE";
    static_assert(sizeof(value) == 18U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

void curve25519_field_multiply(
    std::int64_t output[10],
    const std::int64_t left[10],
    const std::int64_t right[10]) noexcept;
void derive_hmac_v2_digest(
    const std::byte* key,
    std::size_t key_size,
    std::byte* digest) noexcept;
void derive_ror8_v2_digest(const char* text, std::uint8_t digest[32]) noexcept;
bool compute_sha256_hex(
    const void* input,
    std::size_t input_size,
    char* output,
    std::size_t output_capacity) noexcept;
void clear_sensitive_privilege_material(void* memory, std::size_t size) noexcept;

bool derive_ephemeral_payload_key(
    std::span<const std::byte> peer_component,
    ::makima::payload::crypto::PayloadKey& shared_key) noexcept {
    shared_key.fill(std::byte{});
    if (peer_component.size() < 32) return false;

    ::makima::payload::crypto::EcdhSession session;
    (void)::makima::payload::crypto::initialize_empty_ecdh_session(&session);
    if (!::makima::payload::crypto::initialize_ecdh_session(session)) return false;

    std::array<std::byte, 32> peer{};
    std::copy_n(peer_component.begin(), peer.size(), peer.begin());
    const bool derived = ::makima::payload::crypto::derive_ecdh_shared_secret(
        session, peer, shared_key) != 0;
    if (!derived) {
        ::makima::payload::crypto::destroy_ecdh_session(session);
        return false;
    }

    std::array<std::int64_t, 10> peer_limbs{};
    std::array<std::int64_t, 10> public_limbs{};
    std::array<std::int64_t, 10> product{};
    for (std::size_t index = 0; index < peer_limbs.size(); ++index) {
        peer_limbs[index] = static_cast<std::int64_t>(
            std::to_integer<unsigned char>(peer[index % peer.size()]));
        public_limbs[index] = static_cast<std::int64_t>(
            std::to_integer<unsigned char>(session.public_component[index % session.public_component.size()]));
    }
    curve25519_field_multiply(product.data(), peer_limbs.data(), public_limbs.data());

    std::array<std::byte, 32> hmac_digest{};
    derive_hmac_v2_digest(shared_key.data(), shared_key.size(), hmac_digest.data());
    std::array<char, 160> algorithm_context{};
    static const char* const algorithm_context_format =
        allocate_algorithm_context_format(
            reinterpret_cast<const std::uint8_t*>(0x1414D92A2ull));
    std::snprintf(
        algorithm_context.data(), algorithm_context.size(), algorithm_context_format,
        "ECDH", "curve25519", "HMAC-SHA256", "ROR8-v2", "authenticated-payload");
    std::array<std::uint8_t, 32> transport_material_digest{};
    if (!compute_sha256(
            algorithm_context.data(), std::strlen(algorithm_context.data()),
            transport_material_digest.data())) {
        clear_sensitive_privilege_material(shared_key.data(), shared_key.size());
        ::makima::payload::crypto::destroy_ecdh_session(session);
        return false;
    }
    std::array<std::uint8_t, 32> label_digest{};
    derive_ror8_v2_digest("curve25519 authenticated payload", label_digest.data());
    std::array<char, 65> peer_hash{};
    if (!compute_sha256_hex(peer.data(), peer.size(), peer_hash.data(), peer_hash.size())) {
        clear_sensitive_privilege_material(shared_key.data(), shared_key.size());
        ::makima::payload::crypto::destroy_ecdh_session(session);
        return false;
    }
    for (std::size_t index = 0; index < shared_key.size(); ++index) {
        shared_key[index] ^= hmac_digest[index];
        shared_key[index] ^= std::byte{label_digest[index]};
        shared_key[index] ^= std::byte{transport_material_digest[index]};
        shared_key[index] ^= std::byte{static_cast<unsigned char>(product[index % product.size()])};
        shared_key[index] ^= std::byte{static_cast<unsigned char>(peer_hash[index])};
    }
    clear_sensitive_privilege_material(hmac_digest.data(), hmac_digest.size());
    clear_sensitive_privilege_material(label_digest.data(), label_digest.size());
    clear_sensitive_privilege_material(
        transport_material_digest.data(), transport_material_digest.size());
    clear_sensitive_privilege_material(algorithm_context.data(), algorithm_context.size());
    clear_sensitive_privilege_material(product.data(), sizeof(product));
    ::makima::payload::crypto::destroy_ecdh_session(session);
    return true;
}

}
