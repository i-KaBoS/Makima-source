#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace makima::application {

enum class ControlMessageType {
    notification,
    refresh,
    ping,
    kill,
    unknown,
};

ControlMessageType classify_control_message(std::string_view message) noexcept;
std::string serialize_pong(std::int64_t client_time);
std::string serialize_notification_event(std::string_view notification_json);
std::string_view refresh_session_event() noexcept;
std::string_view control_session_kill_event() noexcept;
std::string_view control_session_kill_reason() noexcept;

}
