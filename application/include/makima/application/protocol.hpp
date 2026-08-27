#pragma once

#include "makima/application/common.hpp"

#include <chrono>
#include <optional>

namespace makima::application {

inline constexpr std::string_view sync_endpoint = "https://makima.rip/api/v3/loader/sync";
inline constexpr std::string_view bootstrap_secret = "makima-bootstrap-v1";
inline constexpr std::string_view session_label{"makima-v1\x01", 10};
inline constexpr std::string_view control_extract_key = "websocket";
inline constexpr std::string_view control_session_label{"makima-ws-v1\x01", 13};
inline constexpr std::string_view payload_label = "makima-payload-L1";
inline constexpr std::string_view binding_label = "makima-payload-L2";
inline constexpr std::string_view encryption_label = "makima-l2-enc";
inline constexpr std::string_view authentication_label = "makima-l2-mac";

enum class Opcode : std::uint16_t {
    client_hello = 0x01,
    server_hello = 0x02,
    login = 0x10,
    launch_ticket = 0x30,
    payload = 0x40,
    redeem = 0x50,
    update_status = 0x70,
    security_event = 0xA0,
    control_ticket = 0xB0,
    auxiliary_payload = 0xC0,
    discord_start = 0xE0,
    notifications = 0xF0,
    connection_probe = 0x100,
};

struct KeyPair {
    Bytes private_key;
    Hash256 public_key{};
};

class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;
    virtual Bytes random_bytes(std::size_t count) = 0;
    virtual Hash256 sha256(std::span<const std::uint8_t> input) = 0;
    virtual Hash256 hmac_sha256(
        std::span<const std::uint8_t> key,
        std::span<const std::uint8_t> input) = 0;
    virtual Bytes aes256_gcm_encrypt(
        const Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> associated_data) = 0;
    virtual Bytes aes256_gcm_decrypt(
        const Hash256& key,
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext_and_tag,
        std::span<const std::uint8_t> associated_data) = 0;
    virtual Bytes aes256_cbc_decrypt(
        const Hash256& key,
        std::span<const std::uint8_t, 16> iv,
        std::span<const std::uint8_t> ciphertext) = 0;
    virtual KeyPair x25519_generate() = 0;
    virtual Hash256 x25519_exchange(
        std::span<const std::uint8_t> private_key,
        const Hash256& peer_public_key) = 0;
    virtual bool ed25519_verify(
        const Hash256& public_key,
        std::span<const std::uint8_t> signature,
        std::span<const std::uint8_t> message) = 0;
};

struct Frame {
    std::uint64_t sequence{};
    std::uint64_t timestamp_ms{};
    Opcode opcode{};
    Bytes payload;
};

struct HandshakeAttempt {
    Bytes request;
    Bytes private_key;
    Hash256 client_public_key{};
    std::string hwid;
};

struct HandshakeResult {
    Hash256 session_key{};
    std::uint64_t server_time_seconds{};
    std::uint64_t server_session_id{};
};

struct SessionKeySchedule {
    std::array<Hash256, 18> slots{};
};

SessionKeySchedule* reset_session_key_schedule(SessionKeySchedule* schedule) noexcept;

struct LaunchTicket {
    Hash256 salt{};
    Hash256 expected_sha256{};
};

class ProtocolCodec {
public:
    explicit ProtocolCodec(ICryptoProvider& crypto) : crypto_(crypto) {}

    Bytes pack_frame(
        const Hash256& key,
        std::uint64_t sequence,
        Opcode opcode,
        std::span<const std::uint8_t> payload,
        std::uint64_t timestamp_ms);
    Frame unpack_frame(const Hash256& key, std::span<const std::uint8_t> frame);

    HandshakeAttempt begin_handshake(std::string hwid, std::uint64_t timestamp_ms);
    HandshakeResult finish_handshake(
        const HandshakeAttempt& attempt,
        std::span<const std::uint8_t> server_frame);

    static Bytes pack_text(std::string_view value);
    static std::optional<std::string> read_error(std::span<const std::uint8_t> payload);
    static LaunchTicket read_ticket(std::span<const std::uint8_t> payload);

    Hash256 hkdf(
        std::span<const std::uint8_t> input_key,
        std::span<const std::uint8_t> salt,
        std::string_view label);
    Hash256 derive_control_session_key(const Hash256& session_key);
    Bytes decrypt_payload(
        std::span<const std::uint8_t> response_payload,
        const Hash256& session_key,
        const LaunchTicket& ticket,
        std::string_view hwid);

private:
    Hash256 bootstrap_key();
    Hash256 hwid_hash(std::string_view hwid);
    ICryptoProvider& crypto_;
};

}
