#include "makima/application/session_wire.hpp"

#include <cstdio>

namespace makima::application {

ControlMessageType classify_control_message(std::string_view message) noexcept {
    constexpr std::string_view notification = "\"type\":\"notification\"";
    constexpr std::string_view refresh = "\"type\":\"refresh\"";
    constexpr std::string_view ping = "\"type\":\"ping\"";
    constexpr std::string_view kill = "\"type\":\"kill\"";
    if (message.find(notification) != message.npos) return ControlMessageType::notification;
    if (message.find(refresh) != message.npos) return ControlMessageType::refresh;
    if (message.find(ping) != message.npos) return ControlMessageType::ping;
    if (message.find(kill) != message.npos) return ControlMessageType::kill;
    return ControlMessageType::unknown;
}

std::string serialize_pong(std::int64_t client_time) {
    constexpr char pong_format[] = "{\"type\":\"pong\",\"client_time\":%lld}";
    const int count = std::snprintf(
        nullptr, 0, pong_format, static_cast<long long>(client_time));
    std::string output(static_cast<std::size_t>(count) + 1, '\0');
    std::snprintf(
        output.data(), output.size(), pong_format, static_cast<long long>(client_time));
    output.resize(static_cast<std::size_t>(count));
    return output;
}

std::string serialize_notification_event(std::string_view notification_json) {
    constexpr std::string_view prefix = "{\"event\":\"notification\",\"data\":";
    std::string output{prefix};
    output += notification_json;
    output += "}";
    return output;
}

std::string_view refresh_session_event() noexcept {
    return "{\"event\":\"refresh\"}";
}

std::string_view control_session_kill_event() noexcept {
    return "{\"event\":\"session_error\",\"data\":{\"code\":"
        "\"loader.session_ws_killed_by_server\",\"message\":"
        "\"server sent kill message\"}}";
}

std::string_view control_session_kill_reason() noexcept {
    return "server sent kill message";
}

}
