#include "telemetry/reporting/reporting.hpp"

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
#include <process.h>

namespace makima::telemetry::reporting {

struct AsyncTelemetryTask final {
    std::string event_name;
    std::string detail;
    std::uint32_t severity{};
};

static unsigned __stdcall emit_async_telemetry(void* parameter) noexcept {
    std::unique_ptr<AsyncTelemetryTask> task{static_cast<AsyncTelemetryTask*>(parameter)};
    if (task != nullptr) {
        submit_security_telemetry(task->event_name, task->severity, task->detail);
    }
    return 0;
}

void async_capture_and_report_wrapper(
    const char* event_name,
    std::uint32_t severity,
    const char* detail) noexcept {
    if (event_name == nullptr || *event_name == '\0' || detail == nullptr) return;
    auto task = std::make_unique<AsyncTelemetryTask>();
    task->event_name = event_name;
    task->detail = detail;
    task->severity = severity;
    unsigned thread_id = 0;
    const uintptr_t thread = _beginthreadex(
        nullptr, 0, emit_async_telemetry, task.get(), 0, &thread_id);
    if (thread == 0 || thread_id == 0) return;
    task.release();
    CloseHandle(reinterpret_cast<HANDLE>(thread));
}

void sync_capture_and_report_wrapper(
    const char* event_name,
    std::uint32_t severity,
    const char* detail) noexcept {
    if (event_name == nullptr || *event_name == '\0' || detail == nullptr) return;
    submit_security_telemetry(event_name, severity, detail);
}

}
