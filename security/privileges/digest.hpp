#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace makima::security::privileges {

inline constexpr std::size_t sha256_digest_size = 32;

bool compute_sha256(
    const void* input,
    std::size_t input_size,
    std::uint8_t digest[sha256_digest_size]) noexcept;

void derive_ror8_v2_digest(
    const char* text,
    std::uint8_t digest[sha256_digest_size]) noexcept;

bool compute_sha256_hex(
    const void* input,
    std::size_t input_size,
    char* output,
    std::size_t output_capacity) noexcept;

void derive_hmac_v2_digest(
    const std::byte* key,
    std::size_t key_size,
    std::byte digest[sha256_digest_size]) noexcept;

}
