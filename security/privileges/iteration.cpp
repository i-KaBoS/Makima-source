#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <windows.h>

#include "digest.hpp"

namespace makima::security::privileges {

namespace {


char* allocate_ror8_v2_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[15] = "makima-ror8-v2";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




char* allocate_lowercase_hex_byte_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[5] = "%02x";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

}




void derive_ror8_v2_digest(
    const char* text,
    std::uint8_t digest[sha256_digest_size]) noexcept {
    static const char* const label_text = allocate_ror8_v2_label(
        reinterpret_cast<const std::uint8_t*>(0x1414D92E0ull));
    const std::size_t text_length = std::strlen(text);
    const std::size_t label_length = std::strlen(label_text);
    const std::size_t message_size = text_length + label_length;
    auto* const message = static_cast<std::uint8_t*>(
        HeapAlloc(GetProcessHeap(), 0, message_size));
    if (message == nullptr) return;

    std::memcpy(message, text, text_length);
    std::memcpy(message + text_length, label_text, label_length);
    static_cast<void>(compute_sha256(message, message_size, digest));
    if (message_size != 0) SecureZeroMemory(message, message_size);
    static_cast<void>(HeapFree(GetProcessHeap(), 0, message));
}



bool compute_sha256_hex(
    const void* input,
    std::size_t input_size,
    char* output,
    std::size_t output_capacity) noexcept {
    if (output_capacity < sha256_digest_size * 2U + 1U) {
        return false;
    }

    std::array<std::uint8_t, sha256_digest_size> digest;
    const bool hash_result = compute_sha256(input, input_size, digest.data());
    if (!hash_result) return false;

    static const char* const byte_format = allocate_lowercase_hex_byte_format(
        reinterpret_cast<const std::uint8_t*>(0x1414D92F0ull));
    for (std::size_t index = 0; index < digest.size(); ++index) {
        static_cast<void>(std::snprintf(
            output + index * 2U,
            3,
            byte_format,
            static_cast<unsigned>(digest[index])));
    }
    output[sha256_digest_size * 2U] = '\0';
    return hash_result;
}

}
