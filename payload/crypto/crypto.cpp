#include "payload/crypto/crypto.hpp"

#include "payload/crypto/crypto_internal.hpp"
#include "application/shared/pipelines.hpp"
#include "network/session/crypto_resolvers.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cwchar>
#include <limits>
#include <span>
#include <string_view>
#include <vector>

namespace makima::payload::crypto {
namespace {

[[nodiscard]] ULONG cng_size(std::size_t size) noexcept {
    return size <= std::numeric_limits<ULONG>::max()
        ? static_cast<ULONG>(size)
        : 0;
}

[[nodiscard]] PUCHAR writable_bytes(std::span<std::byte> bytes) noexcept {
    return reinterpret_cast<PUCHAR>(bytes.data());
}

[[nodiscard]] PUCHAR readable_bytes(std::span<const std::byte> bytes) noexcept {
    return reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data()));
}

class AlgorithmHandle final {
public:
    AlgorithmHandle() = default;
    ~AlgorithmHandle() {
        if (value != nullptr) {
            if (const auto close_algorithm =
                    ::makima::application::shared::resolve_bcrypt_close_algorithm_provider()) {
                close_algorithm(value, 0);
            }
        }
    }
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    BCRYPT_ALG_HANDLE value{};
};

class KeyHandle final {
public:
    KeyHandle() = default;
    ~KeyHandle() {
        if (value != nullptr) {
            if (const auto destroy_key =
                    ::makima::application::shared::resolve_bcrypt_destroy_key()) {
                destroy_key(value);
            }
        }
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    BCRYPT_KEY_HANDLE value{};
};

[[nodiscard]] bool open_aes_key(
    const wchar_t* chaining_mode,
    std::span<const std::byte, 32> key,
    AlgorithmHandle& algorithm,
    std::vector<std::byte>& key_object,
    KeyHandle& key_handle) {
    const auto open_algorithm =
        ::makima::network::session::resolve_bcrypt_open_algorithm_provider();
    if (open_algorithm == nullptr || open_algorithm(
            &algorithm.value, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }
    const ULONG mode_bytes = static_cast<ULONG>(
        (std::wcslen(chaining_mode) + 1) * sizeof(wchar_t));
    const auto set_property =
        ::makima::network::session::resolve_bcrypt_set_property();
    if (set_property == nullptr || set_property(
            algorithm.value,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(chaining_mode)),
            mode_bytes,
            0) < 0) {
        return false;
    }
    ULONG object_size{};
    ULONG written{};
    if (BCryptGetProperty(
            algorithm.value,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &written,
            0) < 0 ||
        written != sizeof(object_size)) {
        return false;
    }
    key_object.resize(object_size);
    const auto generate_key =
        ::makima::network::session::resolve_bcrypt_generate_symmetric_key();
    return generate_key != nullptr && generate_key(
               algorithm.value,
               &key_handle.value,
               writable_bytes(key_object),
               object_size,
               readable_bytes(key),
               static_cast<ULONG>(key.size()),
               0) >= 0;
}

[[nodiscard]] bool constant_time_equal(
    std::span<const std::byte> left,
    std::span<const std::byte> right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
    unsigned difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= std::to_integer<unsigned>(left[index] ^ right[index]);
    }
    return difference == 0;
}

}




std::uint64_t derive_payload_keys(
    const PayloadKey& key,
    const std::byte* input,
    std::size_t input_size,
    const std::byte* context,
    std::size_t context_size,
    PayloadKey& output) noexcept {
    if ((input == nullptr && input_size != 0) ||
        (context == nullptr && context_size != 0)) {
        return 0;
    }
    PayloadDigest pseudorandom_key{};
    (void)detail::compute_hmac_sha256(
        key.data(), key.size(), input, input_size, pseudorandom_key.data());
    try {
        const std::span<const std::byte> context_bytes{context, context_size};
        std::vector<std::byte> expansion_input(
            context_bytes.begin(), context_bytes.end());
        expansion_input.push_back(std::byte{1});
        (void)detail::compute_hmac_sha256(
            pseudorandom_key.data(), pseudorandom_key.size(),
            expansion_input.data(), expansion_input.size(), output.data());
        SecureZeroMemory(expansion_input.data(), expansion_input.size());
        SecureZeroMemory(pseudorandom_key.data(), pseudorandom_key.size());
        return 1;
    } catch (...) {
        SecureZeroMemory(pseudorandom_key.data(), pseudorandom_key.size());
        return 0;
    }
}

namespace {

[[nodiscard]] bool decrypt_gcm_packet(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet,
    std::vector<std::byte>& plaintext) noexcept {
    constexpr std::size_t nonce_size = 12;
    constexpr std::size_t tag_size = 16;
    plaintext.clear();
    if (packet.size() < nonce_size + tag_size) {
        return false;
    }
    try {
        const auto nonce = packet.first(nonce_size);
        const auto tag = packet.last(tag_size);
        const auto ciphertext = packet.subspan(
            nonce_size, packet.size() - nonce_size - tag_size);
        AlgorithmHandle algorithm;
        KeyHandle decryption_key;
        std::vector<std::byte> key_object;
        if (!open_aes_key(
                BCRYPT_CHAIN_MODE_GCM, key, algorithm, key_object, decryption_key)) {
            return false;
        }
        const std::byte zero{};
        detail::resize_owned_storage(plaintext, ciphertext.size(), zero);
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
        BCRYPT_INIT_AUTH_MODE_INFO(authentication);
        authentication.pbNonce = readable_bytes(nonce);
        authentication.cbNonce = cng_size(nonce.size());
        authentication.pbTag = readable_bytes(tag);
        authentication.cbTag = cng_size(tag.size());
        ULONG written{};
        if (BCryptDecrypt(
                decryption_key.value,
                readable_bytes(ciphertext),
                cng_size(ciphertext.size()),
                &authentication,
                nullptr,
                0,
                writable_bytes(plaintext),
                cng_size(plaintext.size()),
                &written,
                0) < 0) {
            plaintext.clear();
            return false;
        }
        plaintext.resize(written);
        return true;
    } catch (...) {
        plaintext.clear();
        return false;
    }
}

[[nodiscard]] bool decrypt_cbc_packet(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet,
    std::vector<std::byte>& plaintext) noexcept {
    constexpr std::size_t iv_size = 16;
    constexpr std::size_t tag_size = 32;
    constexpr std::size_t derivation_label_size = 13;
    plaintext.clear();
    if (packet.size() < iv_size + 16 + tag_size ||
        (packet.size() - iv_size - tag_size) % 16 != 0) {
        return false;
    }
    PayloadKey encryption_key{};
    PayloadKey authentication_key{};
    std::array<std::byte, 32> zero_salt{};
    try {



        static const char* const encryption_label =
            detail::allocate_encryption_derivation_label(0x1414D85E5ll);
        static const char* const authentication_label =
            detail::allocate_authentication_derivation_label(0x1414D85F4ll);
        const auto derive_labeled_key = [&](const char* label, PayloadKey& output) {
            PayloadDigest extract_key{};
            std::array<std::byte, 14> input{};
            std::memcpy(input.data(), label, derivation_label_size);
            input[derivation_label_size] = std::byte{1};
            (void)detail::compute_hmac_sha256(
                zero_salt.data(), zero_salt.size(), key.data(), key.size(),
                extract_key.data());
            detail::compute_hmac_sha256(
                extract_key.data(), extract_key.size(), input.data(), input.size(),
                output.data());
            SecureZeroMemory(extract_key.data(), extract_key.size());
        };
        derive_labeled_key(encryption_label, encryption_key);
        derive_labeled_key(authentication_label, authentication_key);
        PayloadDigest computed_tag{};
        const auto authenticated_data = packet.first(packet.size() - tag_size);
        detail::compute_hmac_sha256(
            authentication_key.data(), authentication_key.size(),
            authenticated_data.data(), authenticated_data.size(),
            computed_tag.data());
        if (!constant_time_equal(computed_tag, packet.last(tag_size))) {
            SecureZeroMemory(computed_tag.data(), computed_tag.size());
            return false;
        }
        SecureZeroMemory(computed_tag.data(), computed_tag.size());

        AlgorithmHandle algorithm;
        KeyHandle cbc_key;
        std::vector<std::byte> key_object;
        if (!open_aes_key(
                BCRYPT_CHAIN_MODE_CBC, encryption_key,
                algorithm, key_object, cbc_key)) {
            return false;
        }
        std::array<std::byte, iv_size> iv{};
        std::copy_n(packet.begin(), iv.size(), iv.begin());
        const auto ciphertext = packet.subspan(
            iv_size, packet.size() - iv_size - tag_size);
        const std::byte zero{};
        detail::resize_owned_storage(plaintext, ciphertext.size(), zero);
        ULONG written{};
        if (BCryptDecrypt(
                cbc_key.value,
                readable_bytes(ciphertext),
                cng_size(ciphertext.size()),
                nullptr,
                writable_bytes(iv),
                static_cast<ULONG>(iv.size()),
                writable_bytes(plaintext),
                cng_size(plaintext.size()),
                &written,
                BCRYPT_BLOCK_PADDING) < 0) {
            plaintext.clear();
            return false;
        }
        plaintext.resize(written);
        SecureZeroMemory(iv.data(), iv.size());
        SecureZeroMemory(encryption_key.data(), encryption_key.size());
        SecureZeroMemory(authentication_key.data(), authentication_key.size());
        return true;
    } catch (...) {
        plaintext.clear();
        SecureZeroMemory(encryption_key.data(), encryption_key.size());
        SecureZeroMemory(authentication_key.data(), authentication_key.size());
        return false;
    }
}

}


void decrypt_gcm_payload_packet(
    std::vector<std::byte>& plaintext,
    const PayloadKey& key,
    const std::byte* packet,
    std::size_t packet_size) noexcept {
    plaintext.clear();
    if (packet == nullptr && packet_size != 0) {
        return;
    }
    (void)decrypt_gcm_packet(
        key, std::span<const std::byte>{packet, packet_size}, plaintext);
}


void decrypt_cbc_payload_packet(
    std::vector<std::byte>& plaintext,
    const PayloadKey& key,
    const std::byte* packet,
    std::size_t packet_size) noexcept {
    plaintext.clear();
    if (packet == nullptr && packet_size != 0) {
        return;
    }
    (void)decrypt_cbc_packet(
        key, std::span<const std::byte>{packet, packet_size}, plaintext);
}

}
