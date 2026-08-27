#include <cstddef>
#include <array>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "../../payload/crypto/crypto.hpp"
#include "pipelines.hpp"

namespace makima::application::shared {

bool assign_authenticated_request_text(
    std::string& destination,
    const char* source,
    std::size_t length) {
    if (source == nullptr && length != 0) return false;
    try {
        destination.assign(source == nullptr ? "" : source, length);
        return true;
    } catch (...) {
        destination.clear();
        return false;
    }
}

bool process_authenticated_session_command(
    const ::makima::payload::crypto::PayloadKey& key,
    const ::makima::payload::crypto::PayloadDigest& expected_digest,
    std::span<const std::byte> packet,
    std::string_view request_context) noexcept {
    if (packet.empty() || request_context.empty()) return false;
    SessionRecord record{};
    record.logical_size = static_cast<std::uint32_t>(
        packet.size() - packet.size() % sizeof(std::uint32_t));
    record.words.resize(record.logical_size / sizeof(std::uint32_t));
    if (!record.words.empty()) {
        std::memcpy(record.words.data(), packet.data(), record.logical_size);
    }
    if (serialize_network_session_record(&record) == 0) return false;
    std::vector<std::string_view> message_fields{request_context};
    message_fields.emplace_back(record.serialized);
    std::string session_message;
    assemble_network_session_message(
        &session_message, "authenticated-session", &message_fields);
    if (session_message.empty()) return false;
    std::string request_text(
        reinterpret_cast<const char*>(packet.data()), packet.size());
    AuthenticatedRequestContext derivation{key, {}};
    if (!coordinate_authenticated_request_and_derive_payload_keys(
            &derivation, request_text.c_str())) {
        return false;
    }
    AuthenticatedSessionRequest request{
        derivation.derived_key,
        expected_digest,
        packet.data(),
        packet.size(),
        reinterpret_cast<const std::byte*>(session_message.data()),
        session_message.size()};
    build_and_dispatch_authenticated_session_request(&request);
    return true;
}

}
