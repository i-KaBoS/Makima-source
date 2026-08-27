#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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
#include "pipelines.hpp"

namespace makima::network::session {
bool send_authenticated_request(const std::byte* data, std::size_t size) noexcept;
}

namespace makima::application::shared {

static bool append_json_escape(std::string& output, std::string_view input) {
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char value : input) {
        switch (value) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (value < 0x20U) {
                output += "\\u00";
                output.push_back(hex[value >> 4U]);
                output.push_back(hex[value & 0x0fU]);
            } else {
                output.push_back(static_cast<char>(value));
            }
        }
    }
    return true;
}

std::uint64_t serialize_network_session_record(SessionRecord* record) {
    if (record == nullptr || record->logical_size == 0 || (record->logical_size & 3U) != 0U) return 0;
    const std::size_t word_count = record->logical_size / sizeof(std::uint32_t);
    if (word_count > record->words.size()) return 0;

    record->words.reserve(word_count);
    record->serialized.clear();
    record->serialized.reserve(static_cast<std::size_t>(record->logical_size) * 2U + 64U);
    record->serialized += "{\"logical_size\":" + std::to_string(record->logical_size) + ",\"words\":[";
    bool first = true;
    for (std::size_t index = 0; index < word_count; ++index) {
        if (!std::exchange(first, false)) record->serialized.push_back(',');
        record->serialized += std::to_string(record->words[index]);
    }
    record->words.reserve(word_count + 1U);
    record->serialized += "]}";
    record->committed = !record->serialized.empty();
    return record->committed ? 1U : 0U;
}

void build_and_dispatch_authenticated_session_request(AuthenticatedSessionRequest* request) noexcept {
    if (request == nullptr || request->packet == nullptr || request->packet_size == 0) return;
    PayloadPipelineContext pipeline{request->key, request->expected_digest};
    Octets plaintext(request->packet, request->packet + request->packet_size);
    std::string encrypted_text(
        reinterpret_cast<const char*>(request->packet), request->packet_size);
    std::string context_text;
    if (request->context != nullptr && request->context_size != 0) {
        context_text.assign(
            reinterpret_cast<const char*>(request->context), request->context_size);
    }
    encrypted_text.push_back('\0');
    context_text.push_back('\0');
    (void)orchestrate_authenticated_request_and_debug_driver(
        &pipeline,
        &plaintext,
        encrypted_text.data(),
        context_text.data());
}

void assemble_network_session_message(
    std::string* output,
    const char* command,
    const std::vector<std::string_view>* fields) {
    if (output == nullptr) return;
    output->clear();
    if (command == nullptr || *command == '\0') return;
    if (!assign_authenticated_request_text(*output, command, std::strlen(command))) return;
    output->append("|[");
    if (fields != nullptr && !fields->empty()) {
        append_serialized_request_collection(output, fields->data(), fields->size());
    }
    output->push_back(']');
}

}
