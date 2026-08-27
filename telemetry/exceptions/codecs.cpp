#include "telemetry/exceptions/exceptions.hpp"

#include "telemetry/reporting/reporting.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <winternl.h>

namespace makima::telemetry::exceptions {
namespace {

constexpr std::size_t report_capacity = 0x800;
constexpr std::size_t instruction_byte_count = 16;
constexpr unsigned maximum_stack_frames = 24;

const char* exception_code_name(DWORD code) noexcept {
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_access_violation_name();
        return name;
    }
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_array_bounds_exceeded_name();
        return name;
    }
    case EXCEPTION_BREAKPOINT: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_breakpoint_name();
        return name;
    }
    case EXCEPTION_DATATYPE_MISALIGNMENT: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_datatype_misalignment_name();
        return name;
    }
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_floating_point_divide_by_zero_name();
        return name;
    }
    case EXCEPTION_FLT_INVALID_OPERATION: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_floating_point_invalid_operation_name();
        return name;
    }
    case EXCEPTION_ILLEGAL_INSTRUCTION: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_illegal_instruction_name();
        return name;
    }
    case EXCEPTION_INT_DIVIDE_BY_ZERO: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_integer_divide_by_zero_name();
        return name;
    }
    case EXCEPTION_PRIV_INSTRUCTION: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_privileged_instruction_name();
        return name;
    }
    case EXCEPTION_STACK_OVERFLOW: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_stack_overflow_name();
        return name;
    }
    case 0xc0000409U: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_stack_buffer_overrun_name();
        return name;
    }
    case 0xc0000374U: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_heap_corruption_name();
        return name;
    }
    case 0xc000041dU: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_fatal_user_callback_exception_name();
        return name;
    }
    case 0xe06d7363U: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_cpp_exception_name();
        return name;
    }
    default: {
        static const char* const name =
            ::makima::telemetry::reporting::detail::allocate_unknown_exception_name();
        return name;
    }
    }
}

const char* access_kind(
    const EXCEPTION_RECORD* record,
    std::uintptr_t& target) noexcept {
    static const char* const unavailable =
        ::makima::telemetry::reporting::detail::allocate_access_kind_unavailable();
    target = 0;
    if (record == nullptr ||
        record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION ||
        record->NumberParameters < 2) {
        return unavailable;
    }

    target = record->ExceptionInformation[1];
    switch (record->ExceptionInformation[0]) {
    case 0: {
        static const char* const read =
            ::makima::telemetry::reporting::detail::allocate_access_kind_read();
        return read;
    }
    case 1: {
        static const char* const write =
            ::makima::telemetry::reporting::detail::allocate_access_kind_write();
        return write;
    }
    case 8: {
        static const char* const execute =
            ::makima::telemetry::reporting::detail::allocate_access_kind_execute();
        return execute;
    }
    default:
        return unavailable;
    }
}

bool format_instruction_bytes(
    const void* instruction_address,
    std::array<char, 64>& output) noexcept {
    output.fill('\0');
    if (instruction_address == nullptr) {
        static const char* const unmapped =
            ::makima::telemetry::reporting::detail::allocate_instruction_bytes_unmapped();
        std::memcpy(
            output.data(),
            unmapped,
            std::strlen(unmapped) + 1);
        return false;
    }

    const auto* bytes = static_cast<const unsigned char*>(instruction_address);
    int length = 0;
    for (std::size_t index = 0; index < instruction_byte_count; ++index) {
        const int written = std::snprintf(
            output.data() + length,
            output.size() - static_cast<std::size_t>(length),
            "%02X",
            bytes[index]);
        if (written <= 0) {
            break;
        }
        length += written;
    }
    return true;
}

int append_stack_frame(
    std::array<char, report_capacity>& stack,
    int length,
    const char* separator,
    std::uintptr_t address,
    std::uintptr_t module_base) noexcept {
    if (length < 0 || length >= 0x7a0) {
        return length;
    }

    const std::uintptr_t relative_address =
        address >= module_base ? address - module_base : 0;
    static const char* const frame_format =
        ::makima::telemetry::reporting::detail::allocate_stack_frame_format();
    const int written = std::snprintf(
        stack.data() + length,
        stack.size() - static_cast<std::size_t>(length),
        frame_format,
        separator,
        static_cast<unsigned long long>(address),
        static_cast<unsigned long long>(relative_address));
    return written > 0 ? length + written : length;
}

void unwind_one_frame(CONTEXT& context) noexcept {
    DWORD64 image_base = 0;
    const PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(
        context.Rip,
        &image_base,
        nullptr);
    if (function != nullptr) {
        PVOID handler_data = nullptr;
        DWORD64 establisher_frame = 0;
        RtlVirtualUnwind(
            0,
            image_base,
            context.Rip,
            function,
            &context,
            &handler_data,
            &establisher_frame,
            nullptr);
        return;
    }

    if (context.Rsp != 0) {
        context.Rip = *reinterpret_cast<const DWORD64*>(context.Rsp);
        context.Rsp += sizeof(DWORD64);
    } else {
        context.Rip = 0;
    }
}

void format_stack_trace(
    const EXCEPTION_POINTERS* exception,
    std::uintptr_t module_base,
    std::array<char, report_capacity>& stack) noexcept {
    stack.fill('\0');
    static const char* const open =
        ::makima::telemetry::reporting::detail::allocate_stack_trace_open();
    int length = std::snprintf(stack.data(), stack.size(), open);

    if (exception != nullptr && exception->ContextRecord != nullptr) {
        CONTEXT context{};
        static_assert(sizeof(context) == 0x4d0);
        std::memcpy(&context, exception->ContextRecord, sizeof(context));

        length = append_stack_frame(
            stack,
            length,
            "",
            static_cast<std::uintptr_t>(context.Rip),
            module_base);
        unwind_one_frame(context);

        for (unsigned frame = 1;
             frame < maximum_stack_frames && context.Rip != 0;
             ++frame) {
            static const char* const separator =
                ::makima::telemetry::reporting::detail::allocate_stack_frame_separator();
            length = append_stack_frame(
                stack,
                length,
                separator,
                static_cast<std::uintptr_t>(context.Rip),
                module_base);
            unwind_one_frame(context);
        }
    }

    if (length >= 0 && static_cast<std::size_t>(length) < stack.size()) {
        static const char* const close =
            ::makima::telemetry::reporting::detail::allocate_stack_trace_close();
        std::snprintf(
            stack.data() + length,
            stack.size() - static_cast<std::size_t>(length),
            close);
    }
}

}

LONG WINAPI format_unhandled_exception_event(
    EXCEPTION_POINTERS* exception) noexcept {
    const EXCEPTION_RECORD* record =
        exception == nullptr ? nullptr : exception->ExceptionRecord;
    const DWORD exception_code =
        record == nullptr ? 0 : record->ExceptionCode;
    const std::uintptr_t instruction_address =
        record == nullptr
            ? 0
            : reinterpret_cast<std::uintptr_t>(record->ExceptionAddress);
    const std::uintptr_t module_base =
        reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const std::uintptr_t relative_address =
        instruction_address == 0 ? 0 : instruction_address - module_base;

    std::uintptr_t access_target = 0;
    const char* const violation_kind = access_kind(record, access_target);

    std::array<char, 64> instruction_bytes{};
    format_instruction_bytes(
        reinterpret_cast<const void*>(instruction_address),
        instruction_bytes);

    std::array<char, report_capacity> stack{};
    format_stack_trace(exception, module_base, stack);

    const DWORD current_thread_identifier = GetCurrentThreadId();
    const char* const exception_name = exception_code_name(exception_code);
    std::array<char, report_capacity> report{};
    static const char* const report_format =
        ::makima::telemetry::reporting::detail::allocate_exception_report_format();
    std::snprintf(
        report.data(),
        report.size(),
        report_format,
        exception_code,
        exception_name,
        static_cast<unsigned long long>(instruction_address),
        static_cast<unsigned long long>(module_base),
        static_cast<unsigned long long>(relative_address),
        violation_kind,
        static_cast<unsigned long long>(access_target),
        instruction_bytes.data(),
        current_thread_identifier,
        stack.data());

    detail::current_unhandled_exception_report = report.data();
    critical_exception_report_thunk();

    if (::makima::telemetry::reporting::primary_thread_identifier != 0 &&
        GetCurrentThreadId() !=
            ::makima::telemetry::reporting::primary_thread_identifier) {
        ExitThread(exception_code);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

}
