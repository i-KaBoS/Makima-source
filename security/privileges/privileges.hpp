#pragma once

#include "payload/crypto/crypto.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <windows.h>

namespace makima::security::privileges {

[[nodiscard]] bool token_has_enabled_privilege(
    HANDLE token,
    const LUID& luid) noexcept;
[[nodiscard]] bool enable_named_privilege(
    const wchar_t* privilege_name) noexcept;
void clear_sensitive_privilege_material(void* memory, std::size_t size) noexcept;
[[nodiscard]] wchar_t* allocate_process_target_truncate_mode(
    const std::uint16_t* protected_source);
[[nodiscard]] bool derive_ephemeral_payload_key(
    std::span<const std::byte> peer_component,
    ::makima::payload::crypto::PayloadKey& shared_key) noexcept;
void curve25519_field_multiply(
    std::int64_t output[10],
    const std::int64_t left[10],
    const std::int64_t right[10]) noexcept;
void enable_debug_and_driver_privileges() noexcept;

}
