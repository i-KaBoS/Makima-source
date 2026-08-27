#include "makima/platform/telemetry.hpp"

#include "makima/platform/bitmap_capture.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <windows.h>

#include <array>
#include <atomic>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace makima::platform {
namespace {

std::string base64_encode(std::span<const std::uint8_t> bytes) {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    encoded.reserve(((bytes.size() + 2U) / 3U) * 4U);
    for (std::size_t offset = 0; offset < bytes.size(); offset += 3U) {
        const auto first = static_cast<std::uint32_t>(bytes[offset]);
        const auto second = offset + 1U < bytes.size()
            ? static_cast<std::uint32_t>(bytes[offset + 1U])
            : 0U;
        const auto third = offset + 2U < bytes.size()
            ? static_cast<std::uint32_t>(bytes[offset + 2U])
            : 0U;
        const auto group = (first << 16U) | (second << 8U) | third;
        encoded.push_back(alphabet[(group >> 18U) & 0x3FU]);
        encoded.push_back(alphabet[(group >> 12U) & 0x3FU]);
        encoded.push_back(offset + 1U < bytes.size()
            ? alphabet[(group >> 6U) & 0x3FU]
            : '=');
        encoded.push_back(offset + 2U < bytes.size()
            ? alphabet[group & 0x3FU]
            : '=');
    }
    return encoded;
}

std::string process_list_payload(std::span<const ProcessRecord> processes) {
    std::string inventory{"["};
    inventory.reserve(0x2000);
    bool first = true;
    for (const auto& process : processes) {
        if (!first) {
            inventory.push_back(',');
        }
        first = false;
        inventory.append(format_process_record_json(process));
    }
    inventory.push_back(']');
    return inventory;
}

}

std::string_view exception_event_name(std::uint32_t exception_code) noexcept {
    switch (exception_code) {
    case EXCEPTION_ACCESS_VIOLATION: return "access_violation";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "array_bounds_exceeded";
    case EXCEPTION_BREAKPOINT: return "breakpoint";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "datatype_misalignment";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "floating_point_divide_by_zero";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal_instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "integer_divide_by_zero";
    case EXCEPTION_STACK_OVERFLOW: return "stack_overflow";
    default: return "unhandled_exception";
    }
}



std::string_view security_event_severity_name(SecurityEventSeverity severity) noexcept {
    return ::makima::telemetry::reporting::security_event_severity_c_str(
        static_cast<std::uint32_t>(severity));
}



application::Json build_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details,
    std::span<const ProcessRecord> processes,
    std::span<const std::uint8_t> screenshot_jpeg,
    std::string_view sid) {
    std::string details_payload = details.is_null() ? "{}" : details.dump();
    application::Json::Object event{
        {"event_type", std::string(event_type)},
        {"severity", std::string(security_event_severity_name(severity))},
        {"details", std::move(details_payload)},
        {"process_list", process_list_payload(processes)},
    };
    std::vector<std::string> member_order{
        "event_type", "severity", "details", "process_list"};
    if (!screenshot_jpeg.empty()) {
        event.emplace("screenshot_b64", base64_encode(screenshot_jpeg));
        member_order.emplace_back("screenshot_b64");
    }
    if (!sid.empty()) {
        event.emplace("sid", std::string(sid));
        member_order.emplace_back("sid");
    }
    return application::Json::ordered_object(
        std::move(event), std::move(member_order));
}

application::Json build_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details,
    std::span<const ProcessRecord> processes,
    std::span<const std::uint8_t> screenshot_jpeg) {
    return build_security_event(
        event_type,
        severity,
        std::move(details),
        processes,
        screenshot_jpeg,
        std::string_view{});
}



application::Json collect_security_event(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details,
    std::string_view sid) {
    const auto screenshot = capture_virtual_desktop_jpeg();
    const auto processes = ProcessInventory{}.snapshot();
    return build_security_event(
        event_type, severity, std::move(details), processes, screenshot, sid);
}

application::Json format_unhandled_exception_event(
    std::uint32_t exception_code,
    std::uintptr_t instruction_address,
    std::uint32_t thread_id) {
    return application::Json::Object{
        {"event", std::string(exception_event_name(exception_code))},
        {"exceptionCode", static_cast<double>(exception_code)},
        {"instructionAddress", static_cast<double>(instruction_address)},
        {"threadId", static_cast<double>(thread_id)},
        {"critical", true},
    };
}



EventSubmission SecurityEventSubmitter::submit(
    std::string_view event_type,
    SecurityEventSeverity severity,
    application::Json details) {
    const auto screenshot = capture_virtual_desktop_jpeg();
    const auto processes = ProcessInventory{}.snapshot();
    const auto anonymous_event = build_security_event(
        event_type, severity, details, processes, screenshot);
    const auto authenticated_event = build_security_event(
        event_type, severity, std::move(details), processes, screenshot, client_.hwid());
    return {.response = client_.submit_security_event(
        anonymous_event.dump(), authenticated_event.dump())};
}



std::future<EventSubmission> SecurityEventSubmitter::submit_async(
    std::string event_type,
    SecurityEventSeverity severity,
    application::Json details) {
    return std::async(std::launch::async, [
        this,
        event_type = std::move(event_type),
        severity,
        details = std::move(details)]() mutable {
        return submit(event_type, severity, std::move(details));
    });
}

std::uint32_t current_thread_id() noexcept {
    return GetCurrentThreadId();
}

struct UnhandledExceptionMonitor::State {
    Handler handler;
    LPTOP_LEVEL_EXCEPTION_FILTER previous{};
};

namespace {
std::atomic<UnhandledExceptionMonitor::State*> active_exception_monitor{};

LONG WINAPI report_unhandled_exception(EXCEPTION_POINTERS* pointers) {
    auto* monitor = active_exception_monitor.load(std::memory_order_acquire);
    if (monitor != nullptr && monitor->handler && pointers != nullptr &&
        pointers->ExceptionRecord != nullptr) {
        try {
            monitor->handler(format_unhandled_exception_event(
                pointers->ExceptionRecord->ExceptionCode,
                reinterpret_cast<std::uintptr_t>(
                    pointers->ExceptionRecord->ExceptionAddress),
                current_thread_id()));
        } catch (...) {
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
}

UnhandledExceptionMonitor::UnhandledExceptionMonitor(Handler handler)
    : state_(std::make_unique<State>()) {
    if (!handler) {
        throw application::ApplicationError("unhandled-exception handler cannot be empty");
    }
    State* expected = nullptr;
    if (!active_exception_monitor.compare_exchange_strong(expected, state_.get())) {
        throw application::ApplicationError("an unhandled-exception monitor is already active");
    }
    state_->handler = std::move(handler);
    state_->previous = SetUnhandledExceptionFilter(report_unhandled_exception);
}

UnhandledExceptionMonitor::~UnhandledExceptionMonitor() {
    if (state_) {
        SetUnhandledExceptionFilter(state_->previous);
        State* expected = state_.get();
        active_exception_monitor.compare_exchange_strong(expected, nullptr);
    }
}

}
