#include "makima/platform/crypto_provider.hpp"

#include "tweetnacl.h"
#include "application/shared/pipelines.hpp"
#include "network/session/crypto_resolvers.hpp"
#include "network/shared/crypto_resolvers.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <limits>
#include <span>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {

using makima::application::ApplicationError;
using makima::application::Bytes;
using makima::application::Hash256;

[[noreturn]] void throw_status(const char* operation, NTSTATUS status) {
    std::ostringstream message;
    message << operation << " failed with NTSTATUS 0x" << std::hex
            << static_cast<std::uint32_t>(status);
    throw ApplicationError(message.str());
}

void require_success(const char* operation, NTSTATUS status) {
    if (status < 0) {
        throw_status(operation, status);
    }
}

ULONG checked_size(std::size_t size, const char* field) {
    if (size > std::numeric_limits<ULONG>::max()) {
        throw ApplicationError(std::string{field} + " is too large for CNG");
    }
    return static_cast<ULONG>(size);
}

class AlgorithmHandle final {
public:
    AlgorithmHandle(const wchar_t* identifier, ULONG flags = 0) {
        const auto open_algorithm =
            makima::network::session::resolve_bcrypt_open_algorithm_provider();
        if (open_algorithm == nullptr) {
            throw ApplicationError("BCryptOpenAlgorithmProvider is unavailable");
        }
        require_success(
            "BCryptOpenAlgorithmProvider",
            open_algorithm(&value_, identifier, nullptr, flags));
    }
    ~AlgorithmHandle() {
        if (value_ != nullptr) {
            if (const auto close_algorithm =
                    makima::application::shared::resolve_bcrypt_close_algorithm_provider()) {
                close_algorithm(value_, 0);
            }
        }
    }
    AlgorithmHandle(const AlgorithmHandle&) = delete;
    AlgorithmHandle& operator=(const AlgorithmHandle&) = delete;
    AlgorithmHandle(AlgorithmHandle&& other) noexcept
        : value_(std::exchange(other.value_, nullptr)) {}
    AlgorithmHandle& operator=(AlgorithmHandle&& other) noexcept {
        if (this != &other) {
            if (value_ != nullptr) {
                if (const auto close_algorithm =
                        makima::application::shared::resolve_bcrypt_close_algorithm_provider()) {
                    close_algorithm(value_, 0);
                }
            }
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }
    operator BCRYPT_ALG_HANDLE() const noexcept { return value_; }

private:
    BCRYPT_ALG_HANDLE value_{};
};

class HashHandle final {
public:
    HashHandle(
        BCRYPT_ALG_HANDLE algorithm,
        std::span<std::uint8_t> object,
        std::span<const std::uint8_t> key) {
        require_success(
            "BCryptCreateHash",
            BCryptCreateHash(
                algorithm,
                &value_,
                object.data(),
                checked_size(object.size(), "hash object"),
                const_cast<PUCHAR>(key.data()),
                checked_size(key.size(), "hash key"),
                0));
    }
    ~HashHandle() {
        if (value_ != nullptr) {
            BCryptDestroyHash(value_);
        }
    }
    HashHandle(const HashHandle&) = delete;
    HashHandle& operator=(const HashHandle&) = delete;
    operator BCRYPT_HASH_HANDLE() const noexcept { return value_; }

private:
    BCRYPT_HASH_HANDLE value_{};
};

class KeyHandle final {
public:
    KeyHandle(
        BCRYPT_ALG_HANDLE algorithm,
        std::span<std::uint8_t> object,
        std::span<const std::uint8_t> secret) {
        const auto generate_key =
            makima::network::session::resolve_bcrypt_generate_symmetric_key();
        if (generate_key == nullptr) {
            throw ApplicationError("BCryptGenerateSymmetricKey is unavailable");
        }
        require_success(
            "BCryptGenerateSymmetricKey",
            generate_key(
                algorithm,
                &value_,
                object.data(),
                checked_size(object.size(), "key object"),
                const_cast<PUCHAR>(secret.data()),
                checked_size(secret.size(), "key"),
                0));
    }
    ~KeyHandle() {
        if (value_ != nullptr) {
            if (const auto destroy_key =
                    makima::application::shared::resolve_bcrypt_destroy_key()) {
                destroy_key(value_);
            }
        }
    }
    KeyHandle(const KeyHandle&) = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    operator BCRYPT_KEY_HANDLE() const noexcept { return value_; }

private:
    BCRYPT_KEY_HANDLE value_{};
};

ULONG property_u32(BCRYPT_HANDLE handle, const wchar_t* property) {
    ULONG value = 0;
    ULONG written = 0;
    require_success(
        "BCryptGetProperty",
        BCryptGetProperty(
            handle,
            property,
            reinterpret_cast<PUCHAR>(&value),
            sizeof(value),
            &written,
            0));
    if (written != sizeof(value)) {
        throw ApplicationError("CNG returned a malformed integer property");
    }
    return value;
}

void set_chain_mode(BCRYPT_ALG_HANDLE algorithm, const wchar_t* mode) {
    const auto set_property =
        makima::network::session::resolve_bcrypt_set_property();
    if (set_property == nullptr) {
        throw ApplicationError("BCryptSetProperty is unavailable");
    }
    require_success(
        "BCryptSetProperty(BCRYPT_CHAINING_MODE)",
        set_property(
            algorithm,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)),
            static_cast<ULONG>((std::wcslen(mode) + 1) * sizeof(wchar_t)),
            0));
}

Hash256 hash_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> input) {
    AlgorithmHandle algorithm{
        BCRYPT_SHA256_ALGORITHM,
        key.empty() ? 0UL : BCRYPT_ALG_HANDLE_HMAC_FLAG};
    const auto object_size = property_u32(algorithm, BCRYPT_OBJECT_LENGTH);
    const auto result_size = property_u32(algorithm, BCRYPT_HASH_LENGTH);
    if (result_size != Hash256{}.size()) {
        throw ApplicationError("CNG SHA-256 provider returned an unexpected digest size");
    }
    std::vector<std::uint8_t> object(object_size);
    HashHandle hash{algorithm, object, key};
    require_success(
        "BCryptHashData",
        BCryptHashData(
            hash,
            const_cast<PUCHAR>(input.data()),
            checked_size(input.size(), "hash input"),
            0));
    Hash256 result{};
    require_success(
        "BCryptFinishHash",
        BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0));
    return result;
}

std::pair<AlgorithmHandle, std::vector<std::uint8_t>> open_aes(const wchar_t* mode) {
    AlgorithmHandle algorithm{BCRYPT_AES_ALGORITHM};
    set_chain_mode(algorithm, mode);
    std::vector<std::uint8_t> object(property_u32(algorithm, BCRYPT_OBJECT_LENGTH));
    return {std::move(algorithm), std::move(object)};
}

}

extern "C" void randombytes(unsigned char* output, unsigned long long count) {
    const auto random = makima::network::shared::resolve_bcrypt_random();
    if (count > std::numeric_limits<ULONG>::max() || random == nullptr ||
        random(
            nullptr,
            output,
            static_cast<ULONG>(count),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        std::abort();
    }
}

namespace makima::platform {

application::Bytes CngCryptoProvider::random_bytes(std::size_t count) {
    Bytes result(count);
    if (!result.empty()) {
        const auto random = ::makima::network::shared::resolve_bcrypt_random();
        if (random == nullptr) {
            throw ApplicationError("BCryptGenRandom is unavailable");
        }
        require_success(
            "BCryptGenRandom",
            random(
                nullptr,
                result.data(),
                checked_size(result.size(), "random byte request"),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    }
    return result;
}

application::Hash256 CngCryptoProvider::sha256(std::span<const std::uint8_t> input) {
    return hash_sha256({}, input);
}

application::Hash256 CngCryptoProvider::hmac_sha256(
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> input) {
    return hash_sha256(key, input);
}

application::Bytes CngCryptoProvider::aes256_gcm_encrypt(
    const application::Hash256& key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> plaintext,
    std::span<const std::uint8_t> associated_data) {

    if (nonce.empty()) {
        throw ApplicationError("AES-GCM nonce cannot be empty");
    }
    auto [algorithm, object] = open_aes(BCRYPT_CHAIN_MODE_GCM);
    KeyHandle encryption_key{algorithm, object, key};
    std::array<std::uint8_t, 16> tag{};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
    BCRYPT_INIT_AUTH_MODE_INFO(authentication);
    authentication.pbNonce = const_cast<PUCHAR>(nonce.data());
    authentication.cbNonce = checked_size(nonce.size(), "GCM nonce");
    authentication.pbAuthData = const_cast<PUCHAR>(associated_data.data());
    authentication.cbAuthData = checked_size(associated_data.size(), "GCM associated data");
    authentication.pbTag = tag.data();
    authentication.cbTag = static_cast<ULONG>(tag.size());

    Bytes result(plaintext.size());
    ULONG written = 0;
    const auto encrypt = ::makima::network::session::resolve_bcrypt_encrypt();
    if (encrypt == nullptr) {
        throw ApplicationError("BCryptEncrypt is unavailable");
    }
    require_success(
        "BCryptEncrypt(AES-GCM)",
        encrypt(
            encryption_key,
            const_cast<PUCHAR>(plaintext.data()),
            checked_size(plaintext.size(), "GCM plaintext"),
            &authentication,
            nullptr,
            0,
            result.data(),
            checked_size(result.size(), "GCM ciphertext"),
            &written,
            0));
    result.resize(written);
    result.insert(result.end(), tag.begin(), tag.end());
    return result;
}

application::Bytes CngCryptoProvider::aes256_gcm_decrypt(
    const application::Hash256& key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> ciphertext_and_tag,
    std::span<const std::uint8_t> associated_data) {

    constexpr std::size_t tag_size = 16;
    if (nonce.empty() || ciphertext_and_tag.size() < tag_size) {
        throw ApplicationError("AES-GCM input is missing a nonce or authentication tag");
    }
    const auto ciphertext = ciphertext_and_tag.first(ciphertext_and_tag.size() - tag_size);
    const auto tag = ciphertext_and_tag.last(tag_size);
    auto [algorithm, object] = open_aes(BCRYPT_CHAIN_MODE_GCM);
    KeyHandle decryption_key{algorithm, object, key};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authentication{};
    BCRYPT_INIT_AUTH_MODE_INFO(authentication);
    authentication.pbNonce = const_cast<PUCHAR>(nonce.data());
    authentication.cbNonce = checked_size(nonce.size(), "GCM nonce");
    authentication.pbAuthData = const_cast<PUCHAR>(associated_data.data());
    authentication.cbAuthData = checked_size(associated_data.size(), "GCM associated data");
    authentication.pbTag = const_cast<PUCHAR>(tag.data());
    authentication.cbTag = checked_size(tag.size(), "GCM tag");

    Bytes result(ciphertext.size());
    ULONG written = 0;
    require_success(
        "BCryptDecrypt(AES-GCM)",
        BCryptDecrypt(
            decryption_key,
            const_cast<PUCHAR>(ciphertext.data()),
            checked_size(ciphertext.size(), "GCM ciphertext"),
            &authentication,
            nullptr,
            0,
            result.data(),
            checked_size(result.size(), "GCM plaintext"),
            &written,
            0));
    result.resize(written);
    return result;
}

application::Bytes CngCryptoProvider::aes256_cbc_decrypt(
    const application::Hash256& key,
    std::span<const std::uint8_t, 16> iv,
    std::span<const std::uint8_t> ciphertext) {
    if (ciphertext.empty() || ciphertext.size() % 16 != 0) {
        throw ApplicationError("AES-CBC ciphertext must contain whole blocks");
    }
    auto [algorithm, object] = open_aes(BCRYPT_CHAIN_MODE_CBC);
    KeyHandle decryption_key{algorithm, object, key};
    auto first_iv = std::array<std::uint8_t, 16>{};
    std::copy(iv.begin(), iv.end(), first_iv.begin());
    ULONG required = 0;
    require_success(
        "BCryptDecrypt(AES-CBC size)",
        BCryptDecrypt(
            decryption_key,
            const_cast<PUCHAR>(ciphertext.data()),
            checked_size(ciphertext.size(), "CBC ciphertext"),
            nullptr,
            first_iv.data(),
            static_cast<ULONG>(first_iv.size()),
            nullptr,
            0,
            &required,
            BCRYPT_BLOCK_PADDING));
    Bytes result(required);
    auto second_iv = std::array<std::uint8_t, 16>{};
    std::copy(iv.begin(), iv.end(), second_iv.begin());
    ULONG written = 0;
    require_success(
        "BCryptDecrypt(AES-CBC)",
        BCryptDecrypt(
            decryption_key,
            const_cast<PUCHAR>(ciphertext.data()),
            checked_size(ciphertext.size(), "CBC ciphertext"),
            nullptr,
            second_iv.data(),
            static_cast<ULONG>(second_iv.size()),
            result.data(),
            checked_size(result.size(), "CBC plaintext"),
            &written,
            BCRYPT_BLOCK_PADDING));
    result.resize(written);
    return result;
}

application::KeyPair CngCryptoProvider::x25519_generate() {
    application::KeyPair result;
    result.private_key = random_bytes(32);
    if (crypto_scalarmult_base(result.public_key.data(), result.private_key.data()) != 0) {
        throw ApplicationError("TweetNaCl could not derive an X25519 public key");
    }
    return result;
}

application::Hash256 CngCryptoProvider::x25519_exchange(
    std::span<const std::uint8_t> private_key,
    const application::Hash256& peer_public_key) {
    if (private_key.size() != 32) {
        throw ApplicationError("X25519 private key must contain exactly 32 bytes");
    }
    application::Hash256 result{};
    if (crypto_scalarmult(result.data(), private_key.data(), peer_public_key.data()) != 0 ||
        std::all_of(result.begin(), result.end(), [](std::uint8_t byte) { return byte == 0; })) {
        throw ApplicationError("X25519 peer key produced an invalid shared secret");
    }
    return result;
}

bool CngCryptoProvider::ed25519_verify(
    const application::Hash256& public_key,
    std::span<const std::uint8_t> signature,
    std::span<const std::uint8_t> message) {
    if (signature.size() != 64 ||
        message.size() > std::numeric_limits<unsigned long long>::max() - signature.size()) {
        return false;
    }
    Bytes signed_message(signature.begin(), signature.end());
    signed_message.insert(signed_message.end(), message.begin(), message.end());
    Bytes opened_message(signed_message.size());
    unsigned long long opened_message_size = 0;
    if (crypto_sign_open(
            opened_message.data(),
            &opened_message_size,
            signed_message.data(),
            static_cast<unsigned long long>(signed_message.size()),
            public_key.data()) != 0 ||
        opened_message_size != message.size()) {
        return false;
    }
    return std::equal(message.begin(), message.end(), opened_message.begin());
}

}
