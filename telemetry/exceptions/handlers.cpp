#include "telemetry/exceptions/exceptions.hpp"
#include "telemetry/reporting/reporting.hpp"

namespace makima::telemetry::exceptions {

namespace detail {

const char* current_unhandled_exception_report{};

}

void critical_exception_report_thunk() noexcept {
    const char* const report = detail::current_unhandled_exception_report;
    static const char* const event_name = allocate_unhandled_exception_event_name();
    ::makima::telemetry::reporting::sync_capture_and_report_wrapper(
        event_name,
        3,
        report);
}

}
