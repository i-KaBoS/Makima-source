#include "kernel/symbols/symbols.hpp"
#include "kernel/silo/silo.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string_view>

extern "C" [[noreturn]] void __cdecl _invoke_watson(
    const wchar_t* expression,
    const wchar_t* function_name,
    const wchar_t* file_name,
    unsigned int line_number,
    std::uintptr_t reserved);

namespace makima::runtime::protected_dispatch {



using SymbolObjectDestructor = void (*)(std::uintptr_t object) noexcept;
extern SymbolObjectDestructor symbol_object_destructor;

}

namespace makima::kernel::symbols {




std::string_view cached_live_kernel_debug_directory_error() noexcept {
    static constexpr std::array<char, 31> value{{
        static_cast<char>(0xC5), static_cast<char>(0x9F), static_cast<char>(0x9F),
        static_cast<char>(0xD4), static_cast<char>(0x9F), static_cast<char>(0x9F),
        static_cast<char>(0x12), static_cast<char>(0x42), static_cast<char>(0xDE),
        static_cast<char>(0x3A), static_cast<char>(0xF6), static_cast<char>(0xED),
        static_cast<char>(0xB7), static_cast<char>(0xB4), static_cast<char>(0x9F),
        static_cast<char>(0x59), static_cast<char>(0xF9), static_cast<char>(0xA6),
        static_cast<char>(0xDB), static_cast<char>(0xE2), static_cast<char>(0x1E),
        static_cast<char>(0x9F), static_cast<char>(0x69), static_cast<char>(0x09),
        static_cast<char>(0x9F), static_cast<char>(0x2E), static_cast<char>(0x17),
        static_cast<char>(0x9F), static_cast<char>(0x9F), static_cast<char>(0x63),
        '\0',
    }};
    return {value.data(), value.size() - 1};
}

std::string_view cached_live_kernel_codeview_error() noexcept {
    static constexpr std::array<char, 29> value{{
        static_cast<char>(0x96), static_cast<char>(0x8D), static_cast<char>(0x3F),
        static_cast<char>(0x66), static_cast<char>(0xBD), static_cast<char>(0x9B),
        static_cast<char>(0x19), static_cast<char>(0x1B), static_cast<char>(0xBF),
        static_cast<char>(0x99), static_cast<char>(0x1D), static_cast<char>(0xFE),
        static_cast<char>(0x69), static_cast<char>(0x0F), static_cast<char>(0xDD),
        static_cast<char>(0xA1), static_cast<char>(0xBD), static_cast<char>(0x03),
        static_cast<char>(0x21), static_cast<char>(0x4B), static_cast<char>(0x15),
        static_cast<char>(0xD0), static_cast<char>(0x5E), static_cast<char>(0x77),
        static_cast<char>(0x10), static_cast<char>(0x80), static_cast<char>(0x98),
        static_cast<char>(0xCF), '\0',
    }};
    return {value.data(), value.size() - 1};
}

const std::array<std::byte, 25>
    msf_size_block_count_mismatch_protected_source{{
        std::byte{0x2F}, std::byte{0xC3}, std::byte{0x57}, std::byte{0xF3},
        std::byte{0xA7}, std::byte{0xEA}, std::byte{0xE4}, std::byte{0x8B},
        std::byte{0xEB}, std::byte{0x8C}, std::byte{0xA5}, std::byte{0x17},
        std::byte{0xCC}, std::byte{0xBC}, std::byte{0xE6}, std::byte{0xFC},
        std::byte{0x2C}, std::byte{0xE5}, std::byte{0xE1}, std::byte{0xFB},
        std::byte{0xE5}, std::byte{0xE6}, std::byte{0x3C}, std::byte{0xC9},
        std::byte{0x2C}}};





char* allocate_msf_size_block_count_mismatch_message(
    const std::byte* protected_source) {
    (void)protected_source;
    constexpr char value[] = "size/block-count mismatch";
    static_assert(sizeof(value) == 0x1a);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}





void reset_owned_symbol_text(OwnedSymbolText* owner) noexcept {
    if (owner->capacity >= 16) {
        char* allocation = owner->text.heap_text;
        std::size_t allocation_size = owner->capacity + 1;
        if (allocation_size >= 0x1000) {
            char* original_allocation{};
            std::memcpy(
                &original_allocation,
                allocation - sizeof(original_allocation),
                sizeof(original_allocation));
            const auto alignment_offset =
                static_cast<std::size_t>(allocation - original_allocation);
            if (alignment_offset < sizeof(original_allocation) ||
                alignment_offset > 0x27) {
                _invoke_watson(nullptr, nullptr, nullptr, 0, 0);
            }
            allocation = original_allocation;
            allocation_size += 0x27;
        }
        ::operator delete(allocation, allocation_size);
    }

    owner->size = 0;
    owner->capacity = 15;
    owner->text.inline_text[0] = '\0';
}





void destroy_owned_symbol_object(std::uintptr_t* object) noexcept {
    const std::uintptr_t value = *object;
    if (value != 0) {
        runtime::protected_dispatch::symbol_object_destructor(value);
    }
}

namespace {


constexpr std::array<std::uint16_t, 12> protected_input_for_140770140{{
    0x0039, 0x003B, 0x0035, 0x0070, 0x0017, 0x0035,
    0x0033, 0x003B, 0x003F, 0x0079, 0x0070, 0x0013}};
constexpr std::array<std::uint16_t, 12> protected_input_for_140771700{{
    0x003F, 0x003D, 0x0035, 0x007F, 0x0061, 0x0063,
    0x0061, 0x007E, 0x0060, 0x007E, 0x0060, 0x007E}};
constexpr std::array<std::uint16_t, 12> protected_input_for_140774380{{
    0x0003, 0x0031, 0x0036, 0x0031, 0x0022, 0x0039,
    0x007F, 0x0065, 0x0063, 0x0067, 0x007E, 0x0063}};
constexpr std::array<std::byte, 21> protected_input_for_140776a60{{
    std::byte{0x00}, std::byte{0x00}, std::byte{0x80}, std::byte{0x7C},
    std::byte{0xF5}, std::byte{0x06}, std::byte{0x80}, std::byte{0xF3},
    std::byte{0x80}, std::byte{0xF8}, std::byte{0x25}, std::byte{0x07},
    std::byte{0x25}, std::byte{0x07}, std::byte{0x80}, std::byte{0x84},
    std::byte{0xA5}, std::byte{0x05}, std::byte{0xE5}, std::byte{0x0C},
    std::byte{0x80}}};
constexpr std::array<std::byte, 23> protected_input_for_140778380{{
    std::byte{0x1F}, std::byte{0x90}, std::byte{0x08}, std::byte{0x00},
    std::byte{0x00}, std::byte{0xD2}, std::byte{0x50}, std::byte{0x17},
    std::byte{0x31}, std::byte{0x19}, std::byte{0xC1}, std::byte{0x96},
    std::byte{0x03}, std::byte{0xD6}, std::byte{0x90}, std::byte{0xAA},
    std::byte{0x03}, std::byte{0xE8}, std::byte{0x80}, std::byte{0xE7},
    std::byte{0x40}, std::byte{0xE0}, std::byte{0x80}}};
constexpr std::array<std::byte, 14> protected_input_for_140779fc0{{
    std::byte{0x8E}, std::byte{0x00}, std::byte{0x6C}, std::byte{0x02},
    std::byte{0x21}, std::byte{0x81}, std::byte{0x21}, std::byte{0x81},
    std::byte{0x18}, std::byte{0x01}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x71}, std::byte{0xFA}}};
constexpr std::array<std::byte, 21> protected_input_for_14077ca00{{
    std::byte{0xCF}, std::byte{0x3A}, std::byte{0x9E}, std::byte{0xD8},
    std::byte{0x13}, std::byte{0x00}, std::byte{0x03}, std::byte{0x06},
    std::byte{0x21}, std::byte{0x11}, std::byte{0x9C}, std::byte{0x00},
    std::byte{0x5D}, std::byte{0x90}, std::byte{0x47}, std::byte{0x01},
    std::byte{0x62}, std::byte{0x61}, std::byte{0x5A}, std::byte{0x30},
    std::byte{0xE2}}};
constexpr std::array<std::byte, 25> protected_input_for_14077f600{{
    std::byte{0x01}, std::byte{0xA4}, std::byte{0x79}, std::byte{0x22},
    std::byte{0x08}, std::byte{0x3B}, std::byte{0x04}, std::byte{0x18},
    std::byte{0x28}, std::byte{0xA2}, std::byte{0x91}, std::byte{0x63},
    std::byte{0x02}, std::byte{0xDC}, std::byte{0xCC}, std::byte{0x1B},
    std::byte{0x04}, std::byte{0x8B}, std::byte{0x04}, std::byte{0xCB},
    std::byte{0x04}, std::byte{0x63}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}}};
constexpr std::array<std::byte, 30> protected_input_for_140782bc0{{
    std::byte{0x60}, std::byte{0x26}, std::byte{0x73}, std::byte{0x15},
    std::byte{0x9E}, std::byte{0x0F}, std::byte{0xE3}, std::byte{0x15},
    std::byte{0x00}, std::byte{0x00}, std::byte{0xF5}, std::byte{0x00},
    std::byte{0xD9}, std::byte{0x00}, std::byte{0xD8}, std::byte{0x00},
    std::byte{0xC2}, std::byte{0x00}, std::byte{0xC7}, std::byte{0x0A},
    std::byte{0xD8}, std::byte{0x00}, std::byte{0xC2}, std::byte{0x00},
    std::byte{0x59}, std::byte{0x61}, std::byte{0x8A}, std::byte{0x34},
    std::byte{0x79}, std::byte{0x01}}};
constexpr std::array<std::byte, 40> protected_input_for_140784ba0{{
    std::byte{0x85}, std::byte{0x2B}, std::byte{0x85}, std::byte{0x00},
    std::byte{0xFE}, std::byte{0x01}, std::byte{0xAD}, std::byte{0x01},
    std::byte{0x84}, std::byte{0x00}, std::byte{0xD1}, std::byte{0x35},
    std::byte{0x64}, std::byte{0x0F}, std::byte{0x92}, std::byte{0x03},
    std::byte{0x35}, std::byte{0x01}, std::byte{0x36}, std::byte{0x00},
    std::byte{0xC1}, std::byte{0x0C}, std::byte{0x24}, std::byte{0x01},
    std::byte{0x87}, std::byte{0x13}, std::byte{0x41}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x93}, std::byte{0x04},
    std::byte{0x28}, std::byte{0x0B}, std::byte{0xFB}, std::byte{0x0A},
    std::byte{0xE4}, std::byte{0x02}, std::byte{0x4E}, std::byte{0x07}}};
constexpr std::array<std::byte, 25> protected_input_for_140787e00{{
    std::byte{0xC0}, std::byte{0x05}, std::byte{0x11}, std::byte{0x0E},
    std::byte{0x4C}, std::byte{0x00}, std::byte{0xA6}, std::byte{0x02},
    std::byte{0x17}, std::byte{0x0C}, std::byte{0xDA}, std::byte{0x01},
    std::byte{0x55}, std::byte{0x00}, std::byte{0xC4}, std::byte{0x0F},
    std::byte{0x6D}, std::byte{0x02}, std::byte{0xA7}, std::byte{0x0E},
    std::byte{0xDE}, std::byte{0x04}, std::byte{0x97}, std::byte{0x02},
    std::byte{0x34}}};
constexpr std::array<std::byte, 28> protected_input_for_14078ac80{{
    std::byte{0x0F}, std::byte{0x76}, std::byte{0x01}, std::byte{0x7E},
    std::byte{0x08}, std::byte{0x0D}, std::byte{0x25}, std::byte{0x8C},
    std::byte{0x33}, std::byte{0x0F}, std::byte{0x02}, std::byte{0x52},
    std::byte{0x12}, std::byte{0x85}, std::byte{0x00}, std::byte{0x49},
    std::byte{0x00}, std::byte{0xA2}, std::byte{0x0D}, std::byte{0xD7},
    std::byte{0x33}, std::byte{0xE4}, std::byte{0x5E}, std::byte{0x33},
    std::byte{0x01}, std::byte{0x66}, std::byte{0x11}, std::byte{0xD4}}};
constexpr std::array<std::byte, 23> protected_input_for_14078d7a0{{
    std::byte{0x2D}, std::byte{0x76}, std::byte{0x59}, std::byte{0x09},
    std::byte{0x6D}, std::byte{0xBB}, std::byte{0x00}, std::byte{0xBC},
    std::byte{0x00}, std::byte{0xB6}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x9A}, std::byte{0x40}, std::byte{0x26},
    std::byte{0x66}, std::byte{0xB2}, std::byte{0xD3}, std::byte{0x9F},
    std::byte{0x72}, std::byte{0x83}, std::byte{0x00}}};
constexpr std::array<std::byte, 18> protected_input_for_140642640{{
    std::byte{0xD6}, std::byte{0x31}, std::byte{0x3A}, std::byte{0x86},
    std::byte{0x7C}, std::byte{0x24}, std::byte{0x05}, std::byte{0x23},
    std::byte{0x5E}, std::byte{0x0C}, std::byte{0xF0}, std::byte{0x43},
    std::byte{0x3C}, std::byte{0x00}, std::byte{0x12}, std::byte{0x12},
    std::byte{0x4C}, std::byte{0x05}}};

}





std::uintptr_t cached_decoded_utf16_140770140() noexcept {
    static wchar_t* const value = silo::decode_protected_utf16_140770140(
        protected_input_for_140770140.data());
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_utf16_140771700() noexcept {
    static wchar_t* const value = silo::decode_protected_utf16_140771700(
        reinterpret_cast<std::int64_t>(protected_input_for_140771700.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_utf16_140774380() noexcept {
    static wchar_t* const value = silo::decode_protected_utf16_140774380(
        protected_input_for_140774380.data());
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140776a60() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140776a60(
        protected_input_for_140776a60.data());
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140778380() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140778380(
        reinterpret_cast<std::int64_t>(protected_input_for_140778380.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140779fc0() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140779fc0(
        reinterpret_cast<std::int64_t>(protected_input_for_140779fc0.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_14077ca00() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_14077ca00(
        reinterpret_cast<std::int64_t>(protected_input_for_14077ca00.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_14077f600() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_14077f600(
        reinterpret_cast<std::int64_t>(protected_input_for_14077f600.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140782bc0() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140782bc0(
        reinterpret_cast<std::int64_t>(protected_input_for_140782bc0.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140784ba0() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140784ba0(
        protected_input_for_140784ba0.data());
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140787e00() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_140787e00(
        protected_input_for_140787e00.data());
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_14078ac80() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_14078ac80(
        reinterpret_cast<std::int64_t>(protected_input_for_14078ac80.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_14078d7a0() noexcept {
    static std::byte* const value = silo::decode_protected_bytes_14078d7a0(
        reinterpret_cast<std::int64_t>(protected_input_for_14078d7a0.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}


std::uintptr_t cached_decoded_bytes_140642640() noexcept {
    static std::byte* const value =
        decode_protected_bytes_140642640(
            reinterpret_cast<std::int64_t>(
                protected_input_for_140642640.data()));
    return reinterpret_cast<std::uintptr_t>(value);
}

}
