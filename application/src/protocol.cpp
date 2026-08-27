#include "makima/application/protocol.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace makima::application {
namespace {

constexpr Hash256 server_signing_key{
    0x5f, 0x13, 0xf2, 0xc9, 0xc5, 0xc6, 0x14, 0x22,
    0x4b, 0xa4, 0xf2, 0x0e, 0xbf, 0xfa, 0x93, 0x9b,
    0x43, 0x7c, 0xbe, 0xf0, 0x07, 0x9e, 0x6d, 0x90,
    0x57, 0x0b, 0x13, 0x7b, 0xba, 0x6a, 0x53, 0xfa,
};

std::span<const std::uint8_t> bytes_of(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

void append_u16(Bytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8));
}

void append_u32(Bytes& output, std::uint32_t value) {


    for (unsigned shift = 0; shift < 32; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

void append_u64(Bytes& output, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8)
        output.push_back(static_cast<std::uint8_t>(value >> shift));
}

std::uint16_t read_u16(std::span<const std::uint8_t> input, std::size_t offset) {
    return static_cast<std::uint16_t>(input[offset]) |
           (static_cast<std::uint16_t>(input[offset + 1]) << 8);
}

std::uint32_t read_u32(std::span<const std::uint8_t> input, std::size_t offset) {
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index)
        value |= static_cast<std::uint32_t>(input[offset + index]) << (index * 8);
    return value;
}

std::uint64_t read_u64(std::span<const std::uint8_t> input, std::size_t offset) {
    std::uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index)
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8);
    return value;
}

bool secure_equal(std::span<const std::uint8_t> left, std::span<const std::uint8_t> right) {
    if (left.size() != right.size()) return false;
    std::uint8_t difference = 0;
    for (std::size_t i = 0; i < left.size(); ++i)
        difference |= left[i] ^ right[i];
    return difference == 0;
}

template <std::size_t N>
std::array<std::uint8_t, N> to_array(std::span<const std::uint8_t> input) {
    if (input.size() != N) throw ApplicationError("unexpected fixed-size protocol field");
    std::array<std::uint8_t, N> result{};
    std::copy(input.begin(), input.end(), result.begin());
    return result;
}

}


SessionKeySchedule* reset_session_key_schedule(SessionKeySchedule* schedule) noexcept {
    if (schedule == nullptr) return nullptr;
    for (auto& slot : schedule->slots) slot.fill(0);
    return schedule;
}

Hash256 ProtocolCodec::bootstrap_key() {
    return crypto_.sha256(bytes_of(bootstrap_secret));
}

Hash256 ProtocolCodec::hwid_hash(std::string_view hwid) {
    return crypto_.hmac_sha256(bytes_of("hwid"), bytes_of(hwid));
}

Bytes ProtocolCodec::pack_frame(
    const Hash256& key,
    std::uint64_t sequence,
    Opcode opcode,
    std::span<const std::uint8_t> payload,
    std::uint64_t timestamp_ms) {


    if (payload.size() > std::numeric_limits<std::uint32_t>::max())
        throw ApplicationError("protocol payload exceeds 32-bit length");

    Bytes plaintext;
    plaintext.reserve(40 + payload.size() + 31);
    append_u64(plaintext, sequence);
    append_u64(plaintext, timestamp_ms);
    Bytes marker = crypto_.random_bytes(16);
    if (marker.size() != 16) throw ApplicationError("crypto provider returned a short frame marker");
    plaintext.insert(plaintext.end(), marker.begin(), marker.end());
    append_u16(plaintext, static_cast<std::uint16_t>(opcode));
    append_u16(plaintext, 0);
    append_u32(plaintext, static_cast<std::uint32_t>(payload.size()));
    plaintext.insert(plaintext.end(), payload.begin(), payload.end());

    const std::size_t padded_length = (plaintext.size() + 31U) & ~std::size_t{31U};
    Bytes padding = crypto_.random_bytes(padded_length - plaintext.size());
    if (padding.size() != padded_length - plaintext.size())
        throw ApplicationError("crypto provider returned short frame padding");
    plaintext.insert(plaintext.end(), padding.begin(), padding.end());

    Bytes salt = crypto_.random_bytes(8);
    if (salt.size() != 8) throw ApplicationError("crypto provider returned a short frame salt");
    const Hash256 check_hash = crypto_.hmac_sha256(key, salt);
    Bytes associated_data(salt);
    associated_data.insert(associated_data.end(), check_hash.begin(), check_hash.begin() + 4);
    Bytes nonce(salt);
    nonce.resize(12, 0);
    Bytes encrypted = crypto_.aes256_gcm_encrypt(key, nonce, plaintext, associated_data);

    Bytes frame(associated_data);
    frame.insert(frame.end(), encrypted.begin(), encrypted.end());
    return frame;
}

Frame ProtocolCodec::unpack_frame(const Hash256& key, std::span<const std::uint8_t> frame) {


    if (frame.size() < 28) throw ApplicationError("encrypted frame is too short");
    const auto salt = frame.subspan(0, 8);
    const auto received_check = frame.subspan(8, 4);
    const Hash256 check_hash = crypto_.hmac_sha256(key, salt);
    if (!secure_equal(received_check, std::span<const std::uint8_t>(check_hash).first<4>()))
        throw ApplicationError("frame HMAC check does not match");

    Bytes nonce(salt.begin(), salt.end());
    nonce.resize(12, 0);
    Bytes plaintext = crypto_.aes256_gcm_decrypt(key, nonce, frame.subspan(12), frame.first(12));
    if (plaintext.size() < 40) throw ApplicationError("decrypted frame is too short");
    if (read_u16(plaintext, 34) != 0) throw ApplicationError("frame reserved field is not zero");
    const std::uint32_t payload_length = read_u32(plaintext, 36);
    if (payload_length > plaintext.size() - 40)
        throw ApplicationError("frame payload length exceeds decrypted data");

    Frame decoded;
    decoded.sequence = read_u64(plaintext, 0);
    decoded.timestamp_ms = read_u64(plaintext, 8);
    decoded.opcode = static_cast<Opcode>(read_u16(plaintext, 32));
    decoded.payload.assign(plaintext.begin() + 40, plaintext.begin() + 40 + payload_length);
    return decoded;
}

HandshakeAttempt ProtocolCodec::begin_handshake(std::string hwid, std::uint64_t timestamp_ms) {
    KeyPair keys = crypto_.x25519_generate();
    if (keys.private_key.empty()) throw ApplicationError("X25519 private key is empty");
    const Hash256 binding = hwid_hash(hwid);
    Bytes payload(keys.public_key.begin(), keys.public_key.end());
    payload.insert(payload.end(), binding.begin(), binding.end());

    HandshakeAttempt result;
    result.request = pack_frame(bootstrap_key(), 1, Opcode::client_hello, payload, timestamp_ms);
    if (result.request.size() != 156)
        throw ApplicationError("handshake frame does not have the required 156-byte size");
    result.private_key = std::move(keys.private_key);
    result.client_public_key = keys.public_key;
    result.hwid = std::move(hwid);
    return result;
}

HandshakeResult ProtocolCodec::finish_handshake(
    const HandshakeAttempt& attempt,
    std::span<const std::uint8_t> server_frame) {
    const Frame hello = unpack_frame(bootstrap_key(), server_frame);
    if (hello.opcode != Opcode::server_hello)
        throw ApplicationError("server response is not opcode 0x02");
    if (hello.payload.size() < 128)
        throw ApplicationError("server hello is missing its key, signature, or session metadata");

    const Hash256 server_ephemeral = to_array<32>(std::span<const std::uint8_t>(hello.payload).first(32));
    const auto signature = std::span<const std::uint8_t>(hello.payload).subspan(32, 64);
    Bytes proof(server_ephemeral.begin(), server_ephemeral.end());
    proof.insert(proof.end(), attempt.client_public_key.begin(), attempt.client_public_key.end());
    if (!crypto_.ed25519_verify(server_signing_key, signature, proof))
        throw ApplicationError("server hello Ed25519 signature is invalid");

    const Hash256 shared = crypto_.x25519_exchange(attempt.private_key, server_ephemeral);
    const Hash256 binding = hwid_hash(attempt.hwid);
    const Hash256 seed = crypto_.hmac_sha256(binding, shared);
    HandshakeResult result;
    result.session_key = crypto_.hmac_sha256(seed, bytes_of(session_label));
    result.server_time_seconds = read_u64(hello.payload, 112);
    result.server_session_id = read_u64(hello.payload, 120);
    return result;
}

Bytes ProtocolCodec::pack_text(std::string_view value) {
    if (value.size() > std::numeric_limits<std::uint16_t>::max())
        throw ApplicationError("protocol text exceeds 65535 UTF-8 bytes");
    Bytes output;
    output.reserve(value.size() + 2);
    append_u16(output, static_cast<std::uint16_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
    return output;
}

std::optional<std::string> ProtocolCodec::read_error(std::span<const std::uint8_t> payload) {
    if (payload.size() < 3 || payload[0] != 0) return std::nullopt;
    const std::uint16_t length = read_u16(payload, 1);
    if (length > 512 || length > payload.size() - 3) return std::nullopt;
    return std::string(payload.begin() + 3, payload.begin() + 3 + length);
}

LaunchTicket ProtocolCodec::read_ticket(std::span<const std::uint8_t> payload) {
    if (payload.empty()) throw ApplicationError("opcode 0x30 returned an empty payload");
    if (payload[0] != 1)
        throw ApplicationError(read_error(payload).value_or("opcode 0x30 rejected the launch request"));
    if (payload.size() < 65)
        throw ApplicationError("opcode 0x30 success payload is shorter than 65 bytes");
    LaunchTicket ticket;
    std::copy_n(payload.begin() + 1, 32, ticket.salt.begin());
    std::copy_n(payload.begin() + 33, 32, ticket.expected_sha256.begin());
    return ticket;
}

Hash256 ProtocolCodec::hkdf(
    std::span<const std::uint8_t> input_key,
    std::span<const std::uint8_t> salt,
    std::string_view label) {
    const Hash256 extract_key = crypto_.hmac_sha256(salt, input_key);
    Bytes expansion(bytes_of(label).begin(), bytes_of(label).end());
    expansion.push_back(1);
    return crypto_.hmac_sha256(extract_key, expansion);
}

Hash256 ProtocolCodec::derive_control_session_key(const Hash256& session_key) {
    const Hash256 extracted = crypto_.hmac_sha256(
        bytes_of(control_extract_key), session_key);
    return crypto_.hmac_sha256(extracted, bytes_of(control_session_label));
}

Bytes ProtocolCodec::decrypt_payload(
    std::span<const std::uint8_t> response_payload,
    const Hash256& session_key,
    const LaunchTicket& ticket,
    std::string_view hwid) {
    if (response_payload.empty()) throw ApplicationError("opcode 0x40 returned an empty payload");
    if (response_payload[0] != 1)
        throw ApplicationError(read_error(response_payload).value_or("opcode 0x40 rejected the download request"));
    const auto outer = response_payload.subspan(1);
    if (outer.size() < 28) throw ApplicationError("encrypted content is too short");

    const Hash256 payload_key = hkdf(session_key, ticket.salt, payload_label);
    Bytes inner = crypto_.aes256_gcm_decrypt(
        payload_key, outer.first(12), outer.subspan(12), {});
    if (inner.size() < 64) throw ApplicationError("encrypted L2 payload is too short");
    const std::size_t encrypted_length = inner.size() - 48;
    if (encrypted_length == 0 || encrypted_length % 16 != 0)
        throw ApplicationError("L2 ciphertext is not a positive AES block multiple");

    const Hash256 binding = hwid_hash(hwid);
    const Hash256 bound_key = hkdf(binding, ticket.salt, binding_label);
    const std::array<std::uint8_t, 32> zero_salt{};
    const Hash256 encryption_key = hkdf(bound_key, zero_salt, encryption_label);
    const Hash256 authentication_key = hkdf(bound_key, zero_salt, authentication_label);
    const Hash256 received_mac = to_array<32>(std::span<const std::uint8_t>(inner).last(32));
    const Hash256 computed_mac = crypto_.hmac_sha256(
        authentication_key, std::span<const std::uint8_t>(inner).first(inner.size() - 32));
    if (!secure_equal(received_mac, computed_mac))
        throw ApplicationError("L2 HMAC-SHA256 authentication failed");

    const auto iv = to_array<16>(std::span<const std::uint8_t>(inner).first(16));
    Bytes plaintext = crypto_.aes256_cbc_decrypt(
        encryption_key, iv, std::span<const std::uint8_t>(inner).subspan(16, encrypted_length));
    const Hash256 actual = crypto_.sha256(plaintext);
    if (!secure_equal(actual, ticket.expected_sha256))
        throw ApplicationError("payload SHA-256 does not match the launch ticket");
    return plaintext;
}

}
