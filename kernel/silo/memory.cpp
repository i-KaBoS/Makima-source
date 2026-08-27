#include "kernel/silo/silo.hpp"

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <vector>

namespace makima::kernel::silo {
namespace {

std::size_t aligned_size(std::size_t size, std::size_t alignment) {
    if (alignment <= 1) {
        return size;
    }
    const auto remainder = size % alignment;
    return remainder == 0 ? size : size + alignment - remainder;
}

SiloBuffer allocate_buffer(
    std::span<const std::byte> initial_bytes,
    std::uintptr_t source_va,
    std::size_t alignment,
    std::size_t terminator_bytes = 0) {
    SiloBuffer buffer;
    buffer.source_va = source_va;
    const auto payload_size = initial_bytes.size() + terminator_bytes;
    buffer.bytes.assign(aligned_size(payload_size, alignment), std::byte{});
    std::copy(initial_bytes.begin(), initial_bytes.end(), buffer.bytes.begin());
    return buffer;
}

constexpr std::uint8_t to_uint8(std::byte value) noexcept {
    return std::to_integer<std::uint8_t>(value);
}

constexpr std::byte to_byte(std::uint8_t value) noexcept {
    return static_cast<std::byte>(value);
}

constexpr std::uint8_t rotate_left_byte(
    std::uint8_t value,
    unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift));
}

constexpr std::uint16_t rotate_left_word(
    std::uint16_t value,
    unsigned shift) noexcept {
    return std::rotl(value, static_cast<int>(shift));
}

}

void SiloBuffer::secure_release() noexcept {
    std::fill(bytes.begin(), bytes.end(), std::byte{});
    bytes.clear();
    bytes.shrink_to_fit();
}



SiloBuffer allocate_process_attributes(std::span<const std::byte> input) {
    return allocate_buffer(
        input,
        reinterpret_cast<std::uintptr_t>(&allocate_process_attributes),
        16);
}





wchar_t* decode_protected_utf16_140770140(
    const std::uint16_t* source) {
    auto* output = static_cast<wchar_t*>(::operator new(13U * sizeof(wchar_t)));
    for (std::size_t index = 0; index != 12; ++index) {
        output[index] = static_cast<wchar_t>(source[index] ^ 0x0004U);
    }
    output[12] = L'\0';
    return output;
}



wchar_t* decode_protected_utf16_140771700(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::uint16_t*>(source);
    auto* output = static_cast<wchar_t*>(::operator new(13U * sizeof(wchar_t)));
    output[0] = static_cast<wchar_t>(rotate_left_word(input[0], 13) ^ 0x2032U);
    output[1] = static_cast<wchar_t>(rotate_left_word(input[1], 13) ^ 0x0095U);
    output[2] = static_cast<wchar_t>(rotate_left_word(input[2], 14) ^ 0x00D2U);
    output[3] = static_cast<wchar_t>(rotate_left_word(input[3], 13) ^ 0xC03CU);
    output[4] = static_cast<wchar_t>(rotate_left_word(input[4], 13) ^ 0xA0EEU);
    output[5] = static_cast<wchar_t>(rotate_left_word(input[5], 13) ^ 0x6022U);
    output[6] = static_cast<wchar_t>(rotate_left_word(input[6], 13) ^ 0x20B9U);
    output[7] = static_cast<wchar_t>(rotate_left_word(input[7], 13) ^ 0x6063U);
    output[8] = static_cast<wchar_t>(rotate_left_word(input[8], 13) ^ 0xE03DU);
    output[9] = static_cast<wchar_t>(input[9] ^ 0x0087U);
    output[10] = static_cast<wchar_t>(input[10] ^ 0x0087U);
    output[11] = static_cast<wchar_t>(input[11] ^ 0x0087U);
    output[12] = L'\0';
    return output;
}


std::byte* decode_protected_bytes_140778380(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(24));
    output[0] = to_byte(rotate_left_byte(to_uint8(input[0]), 6) ^ 0xDFU);
    output[1] = to_byte(rotate_left_byte(to_uint8(input[1]), 2) ^ 0x08U);
    output[2] = to_byte(rotate_left_byte(to_uint8(input[2]), 3) ^ 0x97U);
    output[3] = to_byte(rotate_left_byte(to_uint8(input[3]), 3) ^ 0x91U);
    output[4] = to_byte(rotate_left_byte(to_uint8(input[4]), 3) ^ 0x7FU);
    output[5] = to_byte(rotate_left_byte(to_uint8(input[5]), 3) ^ 0xDFU);
    output[6] = to_byte(rotate_left_byte(to_uint8(input[6]), 3) ^ 0x7AU);
    output[7] = to_byte(rotate_left_byte(to_uint8(input[7]), 3) ^ 0x15U);
    output[8] = to_byte(rotate_left_byte(to_uint8(input[8]), 3) ^ 0x23U);
    output[9] = to_byte(rotate_left_byte(to_uint8(input[9]), 3) ^ 0x49U);
    output[10] = to_byte(rotate_left_byte(to_uint8(input[10]), 4) ^ 0xC4U);
    output[11] = to_byte(rotate_left_byte(to_uint8(input[11]), 4) ^ 0xB3U);
    output[12] = to_byte(rotate_left_byte(to_uint8(input[12]), 4) ^ 0x80U);
    output[13] = to_byte(rotate_left_byte(to_uint8(input[13]), 4) ^ 0x19U);
    output[14] = to_byte(rotate_left_byte(to_uint8(input[14]), 4) ^ 0xA2U);
    output[15] = to_byte(rotate_left_byte(to_uint8(input[15]), 4) ^ 0x4CU);
    output[16] = to_byte(rotate_left_byte(to_uint8(input[16]), 4) ^ 0xE6U);
    output[17] = to_byte(rotate_left_byte(to_uint8(input[17]), 4) ^ 0xC4U);
    output[18] = to_byte(rotate_left_byte(to_uint8(input[18]), 1) ^ 0xBFU);
    output[19] = to_byte(rotate_left_byte(to_uint8(input[19]), 1) ^ 0xCDU);
    output[20] = to_byte(rotate_left_byte(to_uint8(input[20]), 5) ^ 0x0EU);
    output[21] = to_byte(rotate_left_byte(to_uint8(input[21]), 5) ^ 0x45U);
    output[22] = to_byte(rotate_left_byte(to_uint8(input[22]), 1) ^ 0xDAU);
    output[23] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_140779fc0(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(15));
    output[0] = to_byte(rotate_left_byte(to_uint8(input[0]), 2) ^ 0xBAU);
    output[1] = to_byte(rotate_left_byte(to_uint8(input[1]), 6) ^ 0x73U);
    output[2] = to_byte(rotate_left_byte(to_uint8(input[2]), 2) ^ 0x51U);
    output[3] = to_byte(rotate_left_byte(to_uint8(input[3]), 2) ^ 0x89U);
    output[4] = to_byte(rotate_left_byte(to_uint8(input[4]), 5) ^ 0x86U);
    output[5] = to_byte(rotate_left_byte(to_uint8(input[5]), 5) ^ 0xFDU);
    output[6] = to_byte(rotate_left_byte(to_uint8(input[6]), 5) ^ 0x26U);
    output[7] = to_byte(rotate_left_byte(to_uint8(input[7]), 5) ^ 0xCBU);
    output[8] = to_byte(rotate_left_byte(to_uint8(input[8]), 1) ^ 0x16U);
    output[9] = to_byte(rotate_left_byte(to_uint8(input[9]), 1) ^ 0xB5U);
    output[10] = to_byte(to_uint8(input[10]) ^ 0x97U);
    output[11] = to_byte(rotate_left_byte(to_uint8(input[11]), 1) ^ 0x07U);
    output[12] = to_byte(rotate_left_byte(to_uint8(input[12]), 1) ^ 0xCEU);
    output[13] = to_byte(to_uint8(input[13]) ^ 0x97U);
    output[14] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_14077ca00(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(22));
    const auto in = [input](std::size_t i) { return to_uint8(input[i]); };
    output[0] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(0) ^ 0x31U) + 0xFBU), 7) ^ 0x24U);
    output[1] = to_byte(rotate_left_byte(static_cast<std::uint8_t>(in(1) + 0x4AU), 7) ^ 0xD5U);
    output[2] = to_byte(static_cast<std::uint8_t>(rotate_left_byte(in(2) ^ 0x35U, 1) + 0xD4U));
    output[3] = to_byte(static_cast<std::uint8_t>(rotate_left_byte(in(3) ^ 0xAEU, 1) + 0x3FU));
    output[4] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(4) ^ 0x0AU) + 0xC1U), 7) ^ 0x1FU);
    output[5] = to_byte(static_cast<std::uint8_t>((in(5) ^ 0x60U) + 0x25U));
    output[6] = to_byte(static_cast<std::uint8_t>((in(6) ^ 0x60U) + 0xAFU));
    output[7] = to_byte(static_cast<std::uint8_t>((in(7) ^ 0x60U) + 0xECU));
    output[8] = to_byte(static_cast<std::uint8_t>((in(8) ^ 0x60U) + 0x39U));
    output[9] = to_byte(static_cast<std::uint8_t>((0x12U - (in(9) ^ 0x26U)) ^ 0x0CU));
    output[10] = to_byte(static_cast<std::uint8_t>((in(10) ^ 0x60U) + 0x9BU));
    output[11] = to_byte(static_cast<std::uint8_t>((in(11) ^ 0x60U) + 0x38U));
    output[12] = to_byte(static_cast<std::uint8_t>((in(12) ^ 0x60U) + 0x90U));
    output[13] = to_byte(in(13) ^ 0xD5U);
    output[14] = to_byte(static_cast<std::uint8_t>(rotate_left_byte(in(14) ^ 0xC6U, 3) + 0x06U));
    output[15] = to_byte(static_cast<std::uint8_t>((0xB5U - (in(15) ^ 0x02U)) ^ 0x28U));
    output[16] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(16) ^ 0x23U) + 0xE9U), 5) ^ 0x66U);
    output[17] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(17) ^ 0x2AU) + 0xE4U), 5) ^ 0x0CU);
    output[18] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(18) ^ 0x1FU) + 0x56U), 5) ^ 0x4AU);
    output[19] = to_byte(rotate_left_byte(static_cast<std::uint8_t>((in(19) ^ 0x31U) + 0x7BU), 5) ^ 0x64U);
    output[20] = to_byte(rotate_left_byte(static_cast<std::uint8_t>(0x2BU - (in(20) ^ 0x18U)), 5) ^ 0x03U);
    output[21] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_14077f600(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(26));
    const auto in = [input](std::size_t i) { return to_uint8(input[i]); };
    output[0] = to_byte(in(0) ^ 0x2FU);
    output[1] = to_byte(rotate_left_byte(in(1), 1) ^ 0x95U);
    output[2] = to_byte(rotate_left_byte(in(2), 2) ^ 0x34U);
    output[3] = to_byte(in(3) ^ 0x20U);
    output[4] = to_byte(rotate_left_byte(in(4), 2) ^ 0xB1U);
    output[5] = to_byte(in(5) ^ 0xBAU);
    output[6] = to_byte(in(6) ^ 0x30U);
    output[7] = to_byte(in(7) ^ 0x75U);
    output[8] = to_byte(rotate_left_byte(in(8), 3) ^ 0xBEU);
    output[9] = to_byte(rotate_left_byte(in(9), 2) ^ 0x7EU);
    output[10] = to_byte(rotate_left_byte(in(10), 3) ^ 0x30U);
    output[11] = to_byte(rotate_left_byte(in(11), 3) ^ 0x6AU);
    output[12] = to_byte(rotate_left_byte(in(12), 3) ^ 0x55U);
    output[13] = to_byte(rotate_left_byte(in(13), 3) ^ 0xE0U);
    output[14] = to_byte(rotate_left_byte(in(14), 3) ^ 0x5EU);
    output[15] = to_byte(rotate_left_byte(in(15), 3) ^ 0x98U);
    output[16] = to_byte(rotate_left_byte(in(16), 3) ^ 0xBEU);
    output[17] = to_byte(rotate_left_byte(in(17), 2) ^ 0x7CU);
    output[18] = to_byte(rotate_left_byte(in(18), 4) ^ 0xEEU);
    output[19] = to_byte(rotate_left_byte(in(19), 4) ^ 0x5FU);
    output[20] = to_byte(rotate_left_byte(in(20), 4) ^ 0xE8U);
    output[21] = to_byte(rotate_left_byte(in(21), 2) ^ 0x69U);
    output[22] = to_byte(rotate_left_byte(in(22), 4) ^ 0xB1U);
    output[23] = to_byte(rotate_left_byte(in(23), 4) ^ 0x9BU);
    output[24] = to_byte(rotate_left_byte(in(24), 4) ^ 0xACU);
    output[25] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_140782bc0(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(31));
    const auto in = [input](std::size_t i) { return to_uint8(input[i]); };
    const auto step = [](std::uint8_t value, std::uint8_t add, unsigned rotate, std::uint8_t mask) {
        return to_byte(rotate_left_byte(static_cast<std::uint8_t>(value + add), rotate) ^ mask);
    };
    output[0] = step(in(0), 0x49, 3, 0x7F); output[1] = step(in(1), 0x7A, 3, 0xF6);
    output[2] = step(in(2), 0x2B, 3, 0x6C); output[3] = step(in(3), 0x20, 4, 0x8B);
    output[4] = step(in(4), 0x0D, 3, 0x5D); output[5] = step(in(5), 0x5E, 3, 0xD7);
    output[6] = step(in(6), 0x10, 4, 0x8A); output[7] = step(in(7), 0x4B, 4, 0xDE);
    output[8] = step(in(8), 0x1A, 5, 0xD7); output[9] = step(in(9), 0x21, 5, 0xF0);
    output[10] = step(in(10), 0x64, 5, 0x98); output[11] = step(in(11), 0x17, 5, 0x36);
    output[12] = step(in(12), 0x77, 5, 0x3A); output[13] = step(in(13), 0x6C, 5, 0x99);
    output[14] = step(in(14), 0x7D, 5, 0x7B); output[15] = step(in(15), 0x5E, 5, 0x5F);
    output[16] = step(in(16), 0x03, 6, 0x69); output[17] = step(in(17), 0x30, 4, 0x88);
    output[18] = step(in(18), 0x42, 6, 0xB9); output[19] = step(in(19), 0x49, 4, 0xFE);
    output[20] = step(in(20), 0x48, 6, 0x38); output[21] = step(in(21), 0x6B, 4, 0xDC);
    output[22] = step(in(22), 0x46, 4, 0x2E); output[23] = step(in(23), 0x0D, 4, 0xBA);
    output[24] = step(in(24), 0x35, 7, 0xC9); output[25] = step(in(25), 0x76, 7, 0x69);
    output[26] = step(in(26), 0x67, 7, 0xE0); output[27] = step(in(27), 0x1C, 7, 0x5E);
    output[28] = step(in(28), 0x21, 7, 0xC3); output[29] = step(in(29), 0x3A, 7, 0x4F);
    output[30] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_140787e00(
    const std::byte* source) {
    auto* output = static_cast<std::byte*>(::operator new(26));
    const auto in = [source](std::size_t i) { return to_uint8(source[i]); };
    const auto step = [](std::uint8_t value, std::uint8_t add, unsigned rotate, std::uint8_t mask) {
        return to_byte(rotate_left_byte(static_cast<std::uint8_t>(value + add), rotate) ^ mask);
    };
    output[0] = step(in(0), 0x0A, 3, 0x0F); output[1] = step(in(1), 0x30, 3, 0x3E);
    output[2] = step(in(2), 0x7D, 3, 0xA4); output[3] = step(in(3), 0x07, 2, 0xBB);
    output[4] = step(in(4), 0x4E, 2, 0x96); output[5] = step(in(5), 0x0C, 3, 0x1F);
    output[6] = step(in(6), 0x02, 3, 0x4F); output[7] = step(in(7), 0x45, 3, 0x65);
    output[8] = step(in(8), 0x18, 4, 0xFF); output[9] = step(in(9), 0x62, 2, 0x26);
    output[10] = step(in(10), 0x23, 5, 0x59); output[11] = step(in(11), 0x10, 5, 0xFC);
    output[12] = step(in(12), 0x38, 5, 0xFB); output[13] = step(in(13), 0x73, 5, 0x53);
    output[14] = step(in(14), 0x2B, 4, 0x2C); output[15] = step(in(15), 0x54, 4, 0xBB);
    output[16] = step(in(16), 0x1C, 5, 0x7E); output[17] = step(in(17), 0x6F, 5, 0xD0);
    output[18] = step(in(18), 0x59, 4, 0x0B); output[19] = step(in(19), 0x1F, 1, 0xED);
    output[20] = step(in(20), 0x4A, 1, 0x43); output[21] = step(in(21), 0x3D, 1, 0xA9);
    output[22] = step(in(22), 0x05, 4, 0xCE); output[23] = step(in(23), 0x4E, 4, 0x5A);
    output[24] = step(in(24), 0x76, 4, 0xD9); output[25] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_14078ac80(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(29));
    const auto in = [input](std::size_t i) { return to_uint8(input[i]); };
    output[0] = to_byte(in(0) ^ 0x93U); output[1] = to_byte(rotate_left_byte(in(1), 1) ^ 0x60U);
    output[2] = to_byte(rotate_left_byte(in(2), 1) ^ 0x14U); output[3] = to_byte(in(3) ^ 0x93U);
    output[4] = to_byte(rotate_left_byte(in(4), 1) ^ 0xFFU); output[5] = to_byte(rotate_left_byte(in(5), 5) ^ 0xA9U);
    output[6] = to_byte(rotate_left_byte(in(6), 5) ^ 0x72U); output[7] = to_byte(in(7) ^ 0x93U);
    output[8] = to_byte(rotate_left_byte(in(8), 5) ^ 0x36U); output[9] = to_byte(in(9) ^ 0x93U);
    output[10] = to_byte(in(10) ^ 0x93U); output[11] = to_byte(rotate_left_byte(in(11), 5) ^ 0xD8U);
    output[12] = to_byte(rotate_left_byte(in(12), 5) ^ 0x77U); output[13] = to_byte(rotate_left_byte(in(13), 6) ^ 0x39U);
    output[14] = to_byte(in(14) ^ 0x93U); output[15] = to_byte(rotate_left_byte(in(15), 6) ^ 0x22U);
    output[16] = to_byte(rotate_left_byte(in(16), 6) ^ 0xAAU); output[17] = to_byte(rotate_left_byte(in(17), 7) ^ 0x17U);
    output[18] = to_byte(rotate_left_byte(in(18), 7) ^ 0x3AU); output[19] = to_byte(rotate_left_byte(in(19), 7) ^ 0x03U);
    output[20] = to_byte(rotate_left_byte(in(20), 7) ^ 0xFFU); output[21] = to_byte(rotate_left_byte(in(21), 3) ^ 0xCCU);
    output[22] = to_byte(rotate_left_byte(in(22), 3) ^ 0x1EU); output[23] = to_byte(rotate_left_byte(in(23), 6) ^ 0x1EU);
    output[24] = to_byte(rotate_left_byte(in(24), 3) ^ 0xE4U); output[25] = to_byte(rotate_left_byte(in(25), 3) ^ 0xAFU);
    output[26] = to_byte(rotate_left_byte(in(26), 6)); output[27] = to_byte(rotate_left_byte(in(27), 6) ^ 0x22U);
    output[28] = std::byte{};
    return output;
}


std::byte* decode_protected_bytes_14078d7a0(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(24));
    const auto in = [input](std::size_t i) { return to_uint8(input[i]); };
    output[0] = to_byte(rotate_left_byte(in(0), 6) ^ 0x1EU); output[1] = to_byte(rotate_left_byte(in(1), 7) ^ 0xCAU);
    output[2] = to_byte(rotate_left_byte(in(2), 6) ^ 0xE4U); output[3] = to_byte(rotate_left_byte(in(3), 2) ^ 0x5AU);
    output[4] = to_byte(in(4) ^ 0x50U); output[5] = to_byte(in(5) ^ 0x50U);
    output[6] = to_byte(rotate_left_byte(in(6), 2) ^ 0x0AU); output[7] = to_byte(rotate_left_byte(in(7), 2) ^ 0x5AU);
    output[8] = to_byte(rotate_left_byte(in(8), 2) ^ 0xC6U); output[9] = to_byte(rotate_left_byte(in(9), 2) ^ 0x22U);
    output[10] = to_byte(in(10) ^ 0x50U); output[11] = to_byte(rotate_left_byte(in(11), 1) ^ 0xCCU);
    output[12] = to_byte(rotate_left_byte(in(12), 1) ^ 0x05U); output[13] = to_byte(rotate_left_byte(in(13), 5) ^ 0x22U);
    output[14] = to_byte(rotate_left_byte(in(14), 5) ^ 0x84U); output[15] = to_byte(rotate_left_byte(in(15), 1) ^ 0x90U);
    output[16] = to_byte(rotate_left_byte(in(16), 5) ^ 0xF6U); output[17] = to_byte(rotate_left_byte(in(17), 1) ^ 0x6FU);
    output[18] = to_byte(rotate_left_byte(in(18), 1) ^ 0x35U); output[19] = to_byte(rotate_left_byte(in(19), 4) ^ 0x8DU);
    output[20] = to_byte(rotate_left_byte(in(20), 4) ^ 0xAFU); output[21] = to_byte(rotate_left_byte(in(21), 6) ^ 0x50U);
    output[22] = to_byte(rotate_left_byte(in(22), 4) ^ 0x50U); output[23] = std::byte{};
    return output;
}



SiloBuffer allocate_command_line(std::span<const std::byte> input) {
    return allocate_buffer(
        input,
        reinterpret_cast<std::uintptr_t>(&allocate_command_line),
        2,
        sizeof(wchar_t));
}




wchar_t* allocate_silo_wide_string_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%ws";
    static_assert(sizeof(value) == 8);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




wchar_t* allocate_silo_device_directory_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"\\Device";
    static_assert(sizeof(value) == 16);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




wchar_t* allocate_silo_device_child_path_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%ws\\Device";
    static_assert(sizeof(value) == 22);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}





char* allocate_nt_allocate_virtual_memory_ex_export_name(
    const std::byte* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtAllocateVirtualMemoryEx";
    static_assert(sizeof(value) == 26);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




wchar_t* allocate_silo_ntdll_module_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"ntdll.dll";
    static_assert(sizeof(value) == 20);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}





wchar_t* allocate_silo_ntoskrnl_image_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"ntoskrnl.exe";
    static_assert(sizeof(value) == 26);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




char* allocate_mm_get_virtual_for_physical_export_name(
    const std::byte* protected_source) {
    (void)protected_source;
    constexpr char value[] = "MmGetVirtualForPhysical";
    static_assert(sizeof(value) == 24);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



SiloBuffer allocate_ksec_output(std::span<const std::byte> input) {
    return allocate_buffer(
        input,
        reinterpret_cast<std::uintptr_t>(&allocate_ksec_output),
        16);
}



SiloBuffer allocate_query_buffer(std::span<const std::byte> input) {
    return allocate_buffer(
        input,
        reinterpret_cast<std::uintptr_t>(&allocate_query_buffer),
        8);
}



wchar_t* allocate_silo_se_debug_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SeDebugPrivilege";
    static_assert(sizeof(value) == 34);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



wchar_t* allocate_silo_se_impersonate_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SeImpersonatePrivilege";
    static_assert(sizeof(value) == 46);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




wchar_t* allocate_lsa_authentication_initialized_event_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"\\SECURITY\\LSA_AUTHENTICATION_INITIALIZED";
    static_assert(sizeof(value) == 0x52);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




wchar_t* allocate_ksecdd_device_path(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"\\Device\\KsecDD";
    static_assert(sizeof(value) == 0x1e);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



void release_process_attributes(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_thread_attributes(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_job_information(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_silo_information(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_security_storage(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_query_storage(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}



void release_namespace_storage(SiloBuffer& buffer) noexcept {
    buffer.secure_release();
}

}
