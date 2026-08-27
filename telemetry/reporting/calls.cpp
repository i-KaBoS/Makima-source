#include "telemetry/reporting/reporting.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <mutex>
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
#include <sddl.h>

namespace makima::network::session {
bool send_authenticated_request(const std::byte* data, std::size_t size) noexcept;
}

namespace makima::telemetry::reporting {

struct TelemetryRecord final {
    std::string event_name;
    std::string detail;
    std::uint32_t severity{};
};

static std::mutex telemetry_mutex;
static std::vector<TelemetryRecord> pending_telemetry;

static std::string current_user_sid_text() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    std::vector<std::byte> storage(required);
    if (required == 0 || !GetTokenInformation(
            token, TokenUser, storage.data(), required, &required)) {
        CloseHandle(token);
        return {};
    }
    CloseHandle(token);
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    LPSTR sid = nullptr;
    if (!ConvertSidToStringSidA(user->User.Sid, &sid) || sid == nullptr) return {};
    std::string text{sid};
    LocalFree(sid);
    return text;
}

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

static void append_json_quoted(
    std::string& output,
    std::string_view input) {
    output.push_back('"');
    append_json_escape(output, input);
    output.push_back('"');
}

static std::string encode_base64(std::span<const std::byte> input) {
    static const char* const alphabet = detail::allocate_base64_alphabet();
    std::string output;
    output.reserve(((input.size() + 2U) / 3U) * 4U);
    for (std::size_t index = 0; index < input.size(); index += 3U) {
        const auto first = std::to_integer<unsigned>(input[index]);
        const auto second = index + 1U < input.size()
            ? std::to_integer<unsigned>(input[index + 1U]) : 0U;
        const auto third = index + 2U < input.size()
            ? std::to_integer<unsigned>(input[index + 2U]) : 0U;
        const unsigned value = (first << 16U) | (second << 8U) | third;
        output.push_back(alphabet[(value >> 18U) & 0x3fU]);
        output.push_back(alphabet[(value >> 12U) & 0x3fU]);
        output.push_back(index + 1U < input.size()
            ? alphabet[(value >> 6U) & 0x3fU] : '=');
        output.push_back(index + 2U < input.size()
            ? alphabet[value & 0x3fU] : '=');
    }
    return output;
}

static std::string compose_security_event_document(
    std::string_view event_name,
    std::string_view severity_name,
    std::string_view detail_document,
    std::string_view process_list_document,
    std::span<const std::byte> screenshot,
    std::string_view sid) {


    std::string request{"{\"event_type\":"};
    append_json_quoted(request, event_name);

    static const char* const severity_member_prefix =
        detail::allocate_security_event_severity_member_prefix();
    request += severity_member_prefix;
    append_json_quoted(request, severity_name);

    static const char* const details_member_prefix =
        detail::allocate_security_event_details_member_prefix();
    request += details_member_prefix;
    if (detail_document.empty()) {
        static const char* const empty_json_object =
            detail::allocate_empty_json_object();
        request += empty_json_object;
    } else {


        request.append(detail_document);
    }

    if (!process_list_document.empty()) {
        static const char* const process_list_member_prefix =
            detail::allocate_security_event_process_list_member_prefix();
        request += process_list_member_prefix;
        request.append(process_list_document);
    }

    if (!screenshot.empty()) {
        static const char* const screenshot_base64_member_prefix =
            detail::allocate_security_event_screenshot_base64_member_prefix();
        request += screenshot_base64_member_prefix;
        append_json_quoted(request, encode_base64(screenshot));
    }

    if (!sid.empty()) {
        request += ",\"sid\":";
        append_json_quoted(request, sid);
    }
    request.push_back('}');
    return request;
}

bool submit_security_telemetry(
    std::string_view event_name,
    std::uint32_t severity,
    std::string_view detail) noexcept {
    if (event_name.empty()) return false;
    const std::string normalized_event = normalize_security_event_name(event_name);
    if (normalized_event.empty()) return false;

    const std::string process_list = "[{\"pid\":" +
        std::to_string(GetCurrentProcessId()) + ",\"threads\":[" +
        std::to_string(GetCurrentThreadId()) + "]}]";
    std::string quoted_detail;
    std::string_view typed_detail = detail;
    if (!detail.empty() && detail.front() != '{' && detail.front() != '[') {
        append_json_quoted(quoted_detail, detail);
        typed_detail = quoted_detail;
    }
    const std::string request = compose_security_event_document(
        normalized_event,
        security_event_severity_name(severity),
        typed_detail,
        process_list,
        {},
        current_user_sid_text());

    {
        std::scoped_lock lock{telemetry_mutex};
        pending_telemetry.push_back(
            {normalized_event, std::string{detail}, severity});
    }
    return ::makima::network::session::send_authenticated_request(
        reinterpret_cast<const std::byte*>(request.data()), request.size());
}

void emit_security_telemetry(std::string_view event_name, std::string_view detail) {
    submit_security_telemetry(event_name, 2, detail);
}

std::vector<TelemetryRecord> drain_security_telemetry() {
    std::scoped_lock lock{telemetry_mutex};
    std::vector<TelemetryRecord> records;
    records.swap(pending_telemetry);
    return records;
}

}
