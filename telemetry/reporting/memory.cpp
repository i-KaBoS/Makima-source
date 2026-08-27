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

namespace makima::telemetry::reporting {

namespace detail {

template <std::size_t Size>
char* allocate_text(const char (&text)[Size]) {
    auto* allocated_text = new char[Size];
    std::copy_n(text, Size, allocated_text);
    return allocated_text;
}

template <std::size_t Size>
wchar_t* allocate_text(const wchar_t (&text)[Size]) {
    auto* allocated_text = new wchar_t[Size];
    std::copy_n(text, Size, allocated_text);
    return allocated_text;
}

char* allocate_base64_alphabet() {
    return allocate_text(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
}

char* allocate_sid_member_prefix() {
    return allocate_text(",\"sid\":");
}

char* allocate_json_object_close() {
    return allocate_text("}");
}

char* allocate_json_quote_escape() {
    return allocate_text("\\\"");
}

char* allocate_json_backslash_escape() {
    return allocate_text("\\\\");
}

char* allocate_json_newline_escape() {
    return allocate_text("\\n");
}

char* allocate_json_carriage_return_escape() {
    return allocate_text("\\r");
}

char* allocate_json_tab_escape() {
    return allocate_text("\\t");
}

char* allocate_json_unicode_escape_format() {
    return allocate_text("\\u%04x");
}

char* allocate_json_array_open() {
    return allocate_text("[");
}

char* allocate_json_array_close() {
    return allocate_text("]");
}

char* allocate_json_element_separator() {
    return allocate_text(",");
}

char* allocate_process_identifier_member_prefix() {
    return allocate_text("{\"pid\":");
}

char* allocate_unsigned_long_long_format() {
    return allocate_text("%llu");
}

char* allocate_process_name_member_prefix() {
    return allocate_text(",\"name\":");
}

char* allocate_idle_process_name() {
    return allocate_text("Idle");
}

char* allocate_system_process_name() {
    return allocate_text("System");
}

char* allocate_threads_member_prefix() {
    return allocate_text(",\"threads\":");
}

char* allocate_unsigned_long_format() {
    return allocate_text("%lu");
}

char* allocate_process_record_close() {
    return allocate_text("}");
}

char* allocate_process_list_close() {
    return allocate_text("]");
}

wchar_t* allocate_jpeg_media_type() {
    return allocate_text(L"image/jpeg");
}

char* allocate_checked_fast_fail_format() {
    return allocate_text("{\"check\":\"%s\",\"fastfail_code\":%u}");
}

char* allocate_anonymous_fast_fail_format() {
    return allocate_text("{\"fastfail_code\":%u}");
}




char* allocate_security_event_severity_member_prefix() {
    return allocate_text(",\"severity\":");
}

char* allocate_security_event_details_member_prefix() {
    return allocate_text(",\"details\":");
}

char* allocate_empty_json_object() {
    return allocate_text("{}");
}

char* allocate_security_event_process_list_member_prefix() {
    return allocate_text(",\"process_list\":");
}

char* allocate_security_event_screenshot_base64_member_prefix() {
    return allocate_text(",\"screenshot_b64\":");
}

char* allocate_access_kind_unavailable() {
    return allocate_text("\xE2\x80\x94");
}

char* allocate_access_kind_read() {
    return allocate_text("read");
}

char* allocate_access_kind_write() {
    return allocate_text("write");
}

char* allocate_access_kind_execute() {
    return allocate_text("execute");
}

char* allocate_instruction_bytes_unmapped() {
    return allocate_text("<unmapped>");
}

char* allocate_stack_trace_open() {
    return allocate_text("[");
}

char* allocate_stack_frame_format() {
    return allocate_text("%s{\"abs\":\"0x%llX\",\"rva\":\"0x%llX\"}");
}

char* allocate_stack_frame_separator() {
    return allocate_text(",");
}

char* allocate_stack_trace_close() {
    return allocate_text("]");
}

char* allocate_access_violation_name() {
    return allocate_text("EXCEPTION_ACCESS_VIOLATION");
}

char* allocate_array_bounds_exceeded_name() {
    return allocate_text("EXCEPTION_ARRAY_BOUNDS_EXCEEDED");
}

char* allocate_breakpoint_name() {
    return allocate_text("EXCEPTION_BREAKPOINT");
}

char* allocate_datatype_misalignment_name() {
    return allocate_text("EXCEPTION_DATATYPE_MISALIGNMENT");
}

char* allocate_floating_point_divide_by_zero_name() {
    return allocate_text("EXCEPTION_FLT_DIVIDE_BY_ZERO");
}

char* allocate_floating_point_invalid_operation_name() {
    return allocate_text("EXCEPTION_FLT_INVALID_OPERATION");
}

char* allocate_illegal_instruction_name() {
    return allocate_text("EXCEPTION_ILLEGAL_INSTRUCTION");
}

char* allocate_integer_divide_by_zero_name() {
    return allocate_text("EXCEPTION_INT_DIVIDE_BY_ZERO");
}

char* allocate_privileged_instruction_name() {
    return allocate_text("EXCEPTION_PRIV_INSTRUCTION");
}

char* allocate_stack_overflow_name() {
    return allocate_text("EXCEPTION_STACK_OVERFLOW");
}

char* allocate_stack_buffer_overrun_name() {
    return allocate_text("STATUS_STACK_BUFFER_OVERRUN");
}

char* allocate_heap_corruption_name() {
    return allocate_text("STATUS_HEAP_CORRUPTION");
}

char* allocate_fatal_user_callback_exception_name() {
    return allocate_text("STATUS_FATAL_USER_CALLBACK_EXCEPTION");
}

char* allocate_cpp_exception_name() {
    return allocate_text("C++ exception");
}

char* allocate_unknown_exception_name() {
    return allocate_text("unknown");
}

char* allocate_exception_report_format() {
    return allocate_text(
        "{\"exception_code\":\"0x%08X\",\"exception_name\":\"%s\","
        "\"address\":\"0x%llX\",\"module_base\":\"0x%llX\","
        "\"rva\":\"0x%llX\",\"av_kind\":\"%s\","
        "\"av_target\":\"0x%llX\",\"insn_bytes\":\"%s\","
        "\"thread_id\":%lu,\"stack\":%s}");
}





char* allocate_security_event_low_severity() {
    return allocate_text("low");
}

char* allocate_security_event_medium_severity() {
    return allocate_text("medium");
}

char* allocate_security_event_high_severity() {
    return allocate_text("high");
}

char* allocate_security_event_critical_severity() {
    return allocate_text("critical");
}

char* allocate_security_event_default_severity() {
    return allocate_text("high");
}


char* allocate_anonymous_security_identity() {
    return allocate_text("anon");
}


char* allocate_security_event_json_prefix() {
    return allocate_text("{\"event_type\":");
}

}



const char* security_event_severity_c_str(std::uint32_t severity) noexcept {
    switch (severity) {
    case 0: {
        static const char* const value =
            detail::allocate_security_event_low_severity();
        return value;
    }
    case 1: {
        static const char* const value =
            detail::allocate_security_event_medium_severity();
        return value;
    }
    case 2: {
        static const char* const value =
            detail::allocate_security_event_high_severity();
        return value;
    }
    case 3: {
        static const char* const value =
            detail::allocate_security_event_critical_severity();
        return value;
    }
    default: {
        static const char* const value =
            detail::allocate_security_event_default_severity();
        return value;
    }
    }
}

std::string_view security_event_severity_name(std::uint32_t severity) noexcept {
    return security_event_severity_c_str(severity);
}

}

