#pragma once

#include "makima/application/protocol.hpp"

namespace makima::platform {

class CngCryptoProvider final : public application::ICryptoProvider {
public:
    application::Bytes random_bytes(std::size_t count) override;
    application::Hash256 sha256(std::span<const std::uint8_t> input) override;
    application::Hash256 hmac_sha256(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> input) override;
    application::Bytes aes256_gcm_encrypt(
        const application::Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> associated_data) override;
    application::Bytes aes256_gcm_decrypt(
        const application::Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext_and_tag,
        std::span<const std::uint8_t> associated_data) override;
    application::Bytes aes256_cbc_decrypt(
        const application::Hash256& key,
        std::span<const std::uint8_t, 16> iv,
        std::span<const std::uint8_t> ciphertext) override;
    application::KeyPair x25519_generate() override;
    application::Hash256 x25519_exchange(
        std::span<const std::uint8_t> private_key,
        const application::Hash256& peer_public_key) override;
    bool ed25519_verify(
        const application::Hash256& public_key,
        std::span<const std::uint8_t> signature,
        std::span<const std::uint8_t> message) override;
};

}
