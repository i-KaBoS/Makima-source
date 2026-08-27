#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <windows.h>

namespace makima::payload::crypto {




[[nodiscard]] const std::string& no_active_subscription_message();
[[nodiscard]] const std::string& payload_download_failed_message();
[[nodiscard]] const wchar_t* encrypted_payload_resource_path();

using PayloadKey = std::array<std::byte, 32>;
using PayloadDigest = std::array<std::byte, 32>;

struct EcdhSession final {
    std::array<std::byte, 32> public_component{};
    bool initialized{};
    std::array<std::byte, 7> reserved{};
    void* algorithm{};
    void* private_key{};
};

static_assert(offsetof(EcdhSession, initialized) == 0x20);
static_assert(offsetof(EcdhSession, algorithm) == 0x28);
static_assert(offsetof(EcdhSession, private_key) == 0x30);
static_assert(sizeof(EcdhSession) == 0x38);

[[nodiscard]] EcdhSession* initialize_empty_ecdh_session(
    EcdhSession* session) noexcept;
void destroy_ecdh_session(EcdhSession& session) noexcept;
[[nodiscard]] bool initialize_ecdh_session(EcdhSession& session) noexcept;
[[nodiscard]] std::uintptr_t derive_ecdh_shared_secret(
    EcdhSession& session,
    const std::array<std::byte, 32>& peer_public_component,
    PayloadKey& shared_secret) noexcept;



void decrypt_gcm_payload_packet(
    std::vector<std::byte>& plaintext,
    const PayloadKey& key,
    const std::byte* packet,
    std::size_t packet_size) noexcept;
void decrypt_cbc_payload_packet(
    std::vector<std::byte>& plaintext,
    const PayloadKey& key,
    const std::byte* packet,
    std::size_t packet_size) noexcept;
void resize_zero_filled_crypto_storage(
    std::vector<std::byte>& buffer,
    std::size_t requested_size);
void bind_shell_folder_path() noexcept;


[[nodiscard]] std::uint64_t derive_payload_keys(
    const PayloadKey& key,
    const std::byte* input,
    std::size_t input_size,
    const std::byte* context,
    std::size_t context_size,
    PayloadKey& output) noexcept;


[[nodiscard]] std::uintptr_t validate_payload_integrity(
    const std::byte* payload,
    std::size_t payload_size,
    const PayloadDigest& expected_digest) noexcept;


[[nodiscard]] std::uint32_t map_payload_into_process(
    char* error_buffer,
    HANDLE process,
    const void* payload,
    std::size_t payload_size) noexcept;


[[nodiscard]] const char* secondary_payload_role_identifier(
    const std::uint8_t* protected_source);
[[nodiscard]] bool is_supported_payload_role(
    const char* role) noexcept;



void bind_bcrypt_decrypt() noexcept;

}
