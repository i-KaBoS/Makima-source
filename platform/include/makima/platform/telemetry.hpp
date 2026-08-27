#pragma once

#include "makima/application/json.hpp"
#include "makima/application/sync_client.hpp"
#include "makima/platform/security_monitor.hpp"
#include "makima/platform/system_services.hpp"

#include <cstdint>
#include <span>
#include <string_view>
#include <functional>
#include <future>
#include <memory>
#include <string>

namespace makima::platform {

[[nodiscard]] std::string_view exception_event_name(std::uint32_t exception_code) noexcept;

enum class SecurityEventSeverity : std::uint8_t {
    low,
    medium,
    high,
    critical,
};

[[nodiscard]] std::string_view security_event_severity_name(
    SecurityEventSeverity severity) noexcept;
[[nodiscard]] application::Json build_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details,
    std::span<const ProcessRecord> processes,
    std::span<const std::uint8_t> screenshot_jpeg,
    std::string_view sid);
[[nodiscard]] application::Json build_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details,
    std::span<const ProcessRecord> processes,
    std::span<const std::uint8_t> screenshot_jpeg);
[[nodiscard]] application::Json collect_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details = application::Json::Object{},
    std::string_view sid = {});
[[nodiscard]] application::Json format_unhandled_exception_event(
    std::uint32_t exception_code,
    std::uintptr_t instruction_address,
    std::uint32_t thread_id);

struct EventSubmission {
    application::Bytes response;
};

class SecurityEventSubmitter final {
public:
    explicit SecurityEventSubmitter(application::SyncClient& client) : client_(client) {}

    [[nodiscard]] EventSubmission submit(
        std::string_view event_type,
        SecurityEventSeverity severity,
        application::Json details = application::Json::Object{});
    [[nodiscard]] std::future<EventSubmission> submit_async(
        std::string event_type,
        SecurityEventSeverity severity,
        application::Json details = application::Json::Object{});

private:
    application::SyncClient& client_;
};

[[nodiscard]] std::uint32_t current_thread_id() noexcept;

class UnhandledExceptionMonitor final {
public:
    using Handler = std::function<void(application::Json)>;
    struct State;

    explicit UnhandledExceptionMonitor(Handler handler);
    ~UnhandledExceptionMonitor();
    UnhandledExceptionMonitor(const UnhandledExceptionMonitor&) = delete;
    UnhandledExceptionMonitor& operator=(const UnhandledExceptionMonitor&) = delete;

private:
    std::unique_ptr<State> state_;
};

}
