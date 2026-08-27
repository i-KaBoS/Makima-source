#include "telemetry/reporting/reporting.hpp"
#include "telemetry/exceptions/exceptions.hpp"

#include <windows.h>

namespace makima::telemetry::reporting {

DWORD primary_thread_identifier{};

void install_unhandled_exception_reporting() noexcept {
    primary_thread_identifier = GetCurrentThreadId();
    SetUnhandledExceptionFilter(
        ::makima::telemetry::exceptions::format_unhandled_exception_event);
}

}
