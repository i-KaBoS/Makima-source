#include "process/discovery/discovery.hpp"
#include "network/session/crypto_resolvers.hpp"
#include "network/shared/crypto_resolvers.hpp"
#include "application/shared/pipelines.hpp"
#include "security/privileges/privileges.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <ranges>
#include <string_view>
#include <utility>

#include <windows.h>
#include <bcrypt.h>

namespace makima::process::discovery {

namespace {

constexpr ULONG aes_key_size = 32;
constexpr ULONG gcm_nonce_size = 12;
constexpr ULONG gcm_tag_size = 16;

PUCHAR mutable_bytes(const void* value) noexcept {
    return static_cast<PUCHAR>(const_cast<void*>(value));
}

}





bool encrypt_aes256_gcm_buffer(
    const std::byte* key,
    const std::byte* plaintext,
    std::uint32_t input_size,
    const std::byte* authenticated_data,
    std::uint32_t authenticated_data_size,
    std::byte* nonce,
    std::byte* ciphertext,
    std::byte* authentication_tag) noexcept {
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE symmetric_key{};
    bool succeeded = false;

    const auto open_algorithm =
        ::makima::network::session::resolve_bcrypt_open_algorithm_provider();
    if (open_algorithm != nullptr &&
        open_algorithm(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0) {
        const auto set_property =
            ::makima::network::session::resolve_bcrypt_set_property();
        if (set_property != nullptr && set_property(
                algorithm,
                BCRYPT_CHAINING_MODE,
                mutable_bytes(BCRYPT_CHAIN_MODE_GCM),
                sizeof(BCRYPT_CHAIN_MODE_GCM),
                0) >= 0) {
            const auto generate_key =
                ::makima::network::session::resolve_bcrypt_generate_symmetric_key();
            if (generate_key != nullptr && generate_key(
                    algorithm,
                    &symmetric_key,
                    nullptr,
                    0,
                    mutable_bytes(key),
                    aes_key_size,
                    0) >= 0) {
                const auto random =
                    ::makima::network::shared::resolve_bcrypt_random();
                if (random != nullptr && random(
                        nullptr,
                        mutable_bytes(nonce),
                        gcm_nonce_size,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0) {
                    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
                    BCRYPT_INIT_AUTH_MODE_INFO(authentication);
                    authentication.pbNonce = mutable_bytes(nonce);
                    authentication.cbNonce = gcm_nonce_size;
                    authentication.pbAuthData = mutable_bytes(authenticated_data);
                    authentication.cbAuthData = authenticated_data_size;
                    authentication.pbTag = mutable_bytes(authentication_tag);
                    authentication.cbTag = gcm_tag_size;
                    ULONG written{};
                    const auto encrypt =
                        ::makima::network::session::resolve_bcrypt_encrypt();
                    succeeded = encrypt != nullptr && encrypt(
                        symmetric_key,
                        mutable_bytes(plaintext),
                        input_size,
                        &authentication,
                        nullptr,
                        0,
                        mutable_bytes(ciphertext),
                        input_size,
                        &written,
                        0) >= 0;
                }
            }
        }
    }

    if (symmetric_key != nullptr) {
        if (const auto destroy_key =
                ::makima::application::shared::resolve_bcrypt_destroy_key()) {
            destroy_key(symmetric_key);
        }
    }
    if (algorithm != nullptr) {
        if (const auto close_algorithm =
                ::makima::application::shared::resolve_bcrypt_close_algorithm_provider()) {
            close_algorithm(algorithm, 0);
        }
    }
    return succeeded;
}




bool decrypt_aes256_gcm_buffer(
    const std::byte* key,
    const std::byte* ciphertext,
    std::uint32_t input_size,
    const std::byte* authenticated_data,
    std::uint32_t authenticated_data_size,
    const std::byte* nonce,
    const std::byte* authentication_tag,
    std::byte* plaintext) noexcept {
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE symmetric_key{};
    bool succeeded = false;

    const auto open_algorithm =
        ::makima::network::session::resolve_bcrypt_open_algorithm_provider();
    if (open_algorithm != nullptr &&
        open_algorithm(&algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0) >= 0) {
        const auto set_property =
            ::makima::network::session::resolve_bcrypt_set_property();
        if (set_property != nullptr && set_property(
                algorithm,
                BCRYPT_CHAINING_MODE,
                mutable_bytes(BCRYPT_CHAIN_MODE_GCM),
                sizeof(BCRYPT_CHAIN_MODE_GCM),
                0) >= 0) {
            const auto generate_key =
                ::makima::network::session::resolve_bcrypt_generate_symmetric_key();
            if (generate_key != nullptr && generate_key(
                    algorithm,
                    &symmetric_key,
                    nullptr,
                    0,
                    mutable_bytes(key),
                    aes_key_size,
                    0) >= 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
                BCRYPT_INIT_AUTH_MODE_INFO(authentication);
                authentication.pbNonce = mutable_bytes(nonce);
                authentication.cbNonce = gcm_nonce_size;
                authentication.pbAuthData = mutable_bytes(authenticated_data);
                authentication.cbAuthData = authenticated_data_size;
                authentication.pbTag = mutable_bytes(authentication_tag);
                authentication.cbTag = gcm_tag_size;
                ULONG written{};
                succeeded = BCryptDecrypt(
                    symmetric_key,
                    mutable_bytes(ciphertext),
                    input_size,
                    &authentication,
                    nullptr,
                    0,
                    mutable_bytes(plaintext),
                    input_size,
                    &written,
                    0) >= 0;
            }
        }
    }

    if (symmetric_key != nullptr) {
        if (const auto destroy_key =
                ::makima::application::shared::resolve_bcrypt_destroy_key()) {
            destroy_key(symmetric_key);
        }
    }
    if (algorithm != nullptr) {
        if (const auto close_algorithm =
                ::makima::application::shared::resolve_bcrypt_close_algorithm_provider()) {
            close_algorithm(algorithm, 0);
        }
    }
    return succeeded;
}


wchar_t* process_target_truncate_mode() {
    static wchar_t* const value =
        ::makima::security::privileges::allocate_process_target_truncate_mode(
            reinterpret_cast<const std::uint16_t*>(0x1414D912Cull));
    return value;
}

}
