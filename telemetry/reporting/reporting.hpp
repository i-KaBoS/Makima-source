#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <windows.h>

namespace makima::telemetry::reporting {

extern DWORD primary_thread_identifier;

[[nodiscard]] std::string normalize_security_event_name(
    std::string_view event_name);
[[nodiscard]] bool submit_security_telemetry(
    std::string_view event_name,
    std::uint32_t severity,
    std::string_view detail) noexcept;
void emit_security_telemetry(
    std::string_view event_name,
    std::string_view detail);
void append_telemetry_json_escaped_text(
    std::string* output,
    const char* input,
    std::size_t length);
void async_capture_and_report_wrapper(
    const char* event_name,
    std::uint32_t severity,
    const char* detail) noexcept;
void sync_capture_and_report_wrapper(
    const char* event_name,
    std::uint32_t severity,
    const char* detail) noexcept;



[[nodiscard]] std::uint32_t registry_telemetry_worker(void* context) noexcept;

[[nodiscard]] bool schedule_security_capture_async() noexcept;
[[nodiscard]] bool schedule_integrity_capture_async(char* state) noexcept;
[[nodiscard]] std::uint64_t report_unauthorized_mapping(
    HANDLE process,
    std::uintptr_t caller,
    std::uintptr_t target,
    std::size_t region_size,
    std::uint64_t allocation_type,
    std::uint64_t protection,
    std::uint64_t mapping_type,
    std::uint32_t process_id,
    std::uint32_t thread_id,
    std::uint32_t status);
[[nodiscard]] std::uint64_t report_remote_or_executable_thread_start(
    HANDLE process,
    std::uint32_t process_id,
    std::uintptr_t caller,
    std::uintptr_t target,
    std::uint64_t creation_flags);
[[nodiscard]] std::uint64_t report_executable_text_protection(
    std::uintptr_t caller,
    const std::uintptr_t* target,
    std::size_t region_size,
    std::uint32_t protection);
[[nodiscard]] std::uint64_t report_external_thread_suspend(
    std::uintptr_t caller,
    std::uintptr_t target);
[[noreturn]] void emit_fast_fail_telemetry(
    std::uint32_t code,
    const char* event_name,
    const char* check);
void install_unhandled_exception_reporting() noexcept;
[[nodiscard]] const char* security_event_severity_c_str(
    std::uint32_t severity) noexcept;
[[nodiscard]] std::string_view security_event_severity_name(
    std::uint32_t severity) noexcept;

namespace detail {




struct RawNarrowStringOwner final {
    union Storage {
        char inline_text[16];
        char* heap_text;
    } text;
    std::size_t size;
    std::size_t capacity;
};

struct SecurityEventSubmissionWorkerContext final {
    RawNarrowStringOwner primary_document;
    RawNarrowStringOwner alternate_document;
};

static_assert(sizeof(RawNarrowStringOwner) == 0x20);
static_assert(offsetof(RawNarrowStringOwner, size) == 0x10);
static_assert(offsetof(RawNarrowStringOwner, capacity) == 0x18);
static_assert(sizeof(SecurityEventSubmissionWorkerContext) == 0x40);
static_assert(offsetof(SecurityEventSubmissionWorkerContext, alternate_document) == 0x20);






void submit_prebuilt_security_event_documents(
    RawNarrowStringOwner* primary_document,
    RawNarrowStringOwner* alternate_document);

[[nodiscard]] std::uint64_t run_security_event_submission_worker(
    SecurityEventSubmissionWorkerContext* context);

[[nodiscard]] char* allocate_base64_alphabet();
[[nodiscard]] char* allocate_sid_member_prefix();
[[nodiscard]] char* allocate_json_object_close();
[[nodiscard]] char* allocate_json_quote_escape();
[[nodiscard]] char* allocate_json_backslash_escape();
[[nodiscard]] char* allocate_json_newline_escape();
[[nodiscard]] char* allocate_json_carriage_return_escape();
[[nodiscard]] char* allocate_json_tab_escape();
[[nodiscard]] char* allocate_json_unicode_escape_format();
[[nodiscard]] char* allocate_json_array_open();
[[nodiscard]] char* allocate_json_array_close();
[[nodiscard]] char* allocate_json_element_separator();
[[nodiscard]] char* allocate_process_identifier_member_prefix();
[[nodiscard]] char* allocate_unsigned_long_long_format();
[[nodiscard]] char* allocate_process_name_member_prefix();
[[nodiscard]] char* allocate_idle_process_name();
[[nodiscard]] char* allocate_system_process_name();
[[nodiscard]] char* allocate_threads_member_prefix();
[[nodiscard]] char* allocate_unsigned_long_format();
[[nodiscard]] char* allocate_process_record_close();
[[nodiscard]] char* allocate_process_list_close();
[[nodiscard]] wchar_t* allocate_jpeg_media_type();
[[nodiscard]] char* allocate_checked_fast_fail_format();
[[nodiscard]] char* allocate_anonymous_fast_fail_format();



[[nodiscard]] char* allocate_security_event_low_severity();
[[nodiscard]] char* allocate_security_event_medium_severity();
[[nodiscard]] char* allocate_security_event_high_severity();
[[nodiscard]] char* allocate_security_event_critical_severity();
[[nodiscard]] char* allocate_security_event_default_severity();
[[nodiscard]] char* allocate_anonymous_security_identity();
[[nodiscard]] char* allocate_security_event_json_prefix();
[[nodiscard]] char* allocate_security_event_severity_member_prefix();
[[nodiscard]] char* allocate_security_event_details_member_prefix();
[[nodiscard]] char* allocate_empty_json_object();
[[nodiscard]] char* allocate_security_event_process_list_member_prefix();
[[nodiscard]] char* allocate_security_event_screenshot_base64_member_prefix();

[[nodiscard]] char* allocate_access_kind_unavailable();
[[nodiscard]] char* allocate_access_kind_read();
[[nodiscard]] char* allocate_access_kind_write();
[[nodiscard]] char* allocate_access_kind_execute();
[[nodiscard]] char* allocate_instruction_bytes_unmapped();
[[nodiscard]] char* allocate_stack_trace_open();
[[nodiscard]] char* allocate_stack_frame_format();
[[nodiscard]] char* allocate_stack_frame_separator();
[[nodiscard]] char* allocate_stack_trace_close();
[[nodiscard]] char* allocate_access_violation_name();
[[nodiscard]] char* allocate_array_bounds_exceeded_name();
[[nodiscard]] char* allocate_breakpoint_name();
[[nodiscard]] char* allocate_datatype_misalignment_name();
[[nodiscard]] char* allocate_floating_point_divide_by_zero_name();
[[nodiscard]] char* allocate_floating_point_invalid_operation_name();
[[nodiscard]] char* allocate_illegal_instruction_name();
[[nodiscard]] char* allocate_integer_divide_by_zero_name();
[[nodiscard]] char* allocate_privileged_instruction_name();
[[nodiscard]] char* allocate_stack_overflow_name();
[[nodiscard]] char* allocate_stack_buffer_overrun_name();
[[nodiscard]] char* allocate_heap_corruption_name();
[[nodiscard]] char* allocate_fatal_user_callback_exception_name();
[[nodiscard]] char* allocate_cpp_exception_name();
[[nodiscard]] char* allocate_unknown_exception_name();
[[nodiscard]] char* allocate_exception_report_format();

}

}
