#pragma once

#include <windows.h>

namespace makima::telemetry::exceptions {

[[nodiscard]] LONG WINAPI format_unhandled_exception_event(
    EXCEPTION_POINTERS* exception) noexcept;
[[nodiscard]] char* allocate_unhandled_exception_event_name();
void critical_exception_report_thunk() noexcept;

namespace detail {

extern const char* current_unhandled_exception_report;

}

}
