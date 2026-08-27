#include "security/anti_analysis/anti_analysis.hpp"
#include "security/environment/environment.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <windows.h>
#include <winternl.h>

#include <intrin.h>
#include <cstring>
#include <iterator>
#include <string_view>

namespace makima::security::anti_analysis {

namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG);



bool loaded_module_names_are_clean() noexcept {
    return loaded_module_names_are_clean_from_peb() != 0;
}





bool invalid_close_handle_raised_exception() noexcept {
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(-1)));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
    return false;
}

const char* report_debugger_signal(
    std::uintptr_t logger_handle,
    std::uintptr_t log_level,
    const char* event_name,
    const char* detail_format,
    const char* detail) noexcept {




    (void)logger_handle;
    (void)log_level;



    (void)detail_format;
    ::makima::telemetry::reporting::emit_security_telemetry(event_name, detail);
    return event_name;
}

}


const char* native_debugger_environment_check(
    std::uintptr_t logger_handle,
    std::uintptr_t log_level) noexcept {
    const auto* peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
    if (peb != nullptr && peb[2] != 0) {
        static const char* const detail = makima::security::environment::
            allocate_peb_being_debugged_detail(
                reinterpret_cast<const std::uint8_t*>(0x1414DC05Cull));
        static const char* const format = makima::security::environment::
            allocate_percent_s_peb_debug_format(
                reinterpret_cast<const std::uint8_t*>(0x1414DC07Full));
        static const char* const event = makima::security::environment::
            allocate_peb_being_debugged_event(
                reinterpret_cast<const std::uint8_t*>(0x1414DC083ull));
        return report_debugger_signal(
            logger_handle,
            log_level,
            event,
            format,
            detail);
    }

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_information = ntdll == nullptr
        ? nullptr
        : reinterpret_cast<NtQueryInformationProcessFn>(
              GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query_information != nullptr) {
        ULONG_PTR debug_port{};
        if (query_information(
                GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(7),
                &debug_port,
                sizeof(debug_port),
                nullptr) == 0 &&
            debug_port != 0) {
            static const char* const detail = makima::security::environment::
                allocate_process_debug_port_detail(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC0A2ull));
            static const char* const format = makima::security::environment::
                allocate_percent_s_process_debug_port_format(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC0C5ull));
            static const char* const event = makima::security::environment::
                allocate_process_debug_port_event(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC0C9ull));
            return report_debugger_signal(
                logger_handle,
                log_level,
                event,
                format,
                detail);
        }

        ULONG debug_flags{1};
        if (query_information(
                GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(0x1f),
                &debug_flags,
                sizeof(debug_flags),
                nullptr) == 0 &&
            debug_flags == 0) {
            static const char* const detail = makima::security::environment::
                allocate_process_debug_flags_detail(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC0E0ull));
            static const char* const format = makima::security::environment::
                allocate_percent_s_process_debug_flags_format(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC104ull));
            static const char* const event = makima::security::environment::
                allocate_process_debug_flags_event(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC108ull));
            return report_debugger_signal(
                logger_handle,
                log_level,
                event,
                format,
                detail);
        }

        HANDLE debug_object{};
        if (query_information(
                GetCurrentProcess(),
                static_cast<PROCESSINFOCLASS>(0x1e),
                &debug_object,
                sizeof(debug_object),
                nullptr) == 0 &&
            debug_object != nullptr) {
            static const char* const detail = makima::security::environment::
                allocate_process_debug_object_detail(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC128ull));
            static const char* const format = makima::security::environment::
                allocate_percent_s_process_debug_object_format(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC157ull));
            static const char* const event = makima::security::environment::
                allocate_process_debug_object_event(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC15Bull));
            return report_debugger_signal(
                logger_handle,
                log_level,
                event,
                format,
                detail);
        }
    }

    BOOL remote_debugger{};
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) &&
        remote_debugger) {
        static const char* const detail = makima::security::environment::
            allocate_remote_debugger_present_detail(
                reinterpret_cast<const std::uint8_t*>(0x1414DC17Cull));
        static const char* const format = makima::security::environment::
            allocate_percent_s_remote_debugger_present_format(
                reinterpret_cast<const std::uint8_t*>(0x1414DC1A9ull));
        static const char* const event = makima::security::environment::
            allocate_remote_debugger_present_event(
                reinterpret_cast<const std::uint8_t*>(0x1414DC1ADull));
        return report_debugger_signal(
            logger_handle,
            log_level,
            event,
            format,
            detail);
    }

    CONTEXT thread_context{};
    thread_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &thread_context) &&
        (thread_context.Dr0 != 0 || thread_context.Dr1 != 0 ||
         thread_context.Dr2 != 0 || thread_context.Dr3 != 0)) {
        return report_debugger_signal(
            logger_handle,
            log_level,
            hardware_breakpoint_event(),
            hardware_breakpoint_format(),
            hardware_breakpoint_detail());
    }

    if (peb != nullptr) {
        ULONG nt_global_flag{};
        std::memcpy(&nt_global_flag, peb + 0xbc, sizeof(nt_global_flag));
        if ((nt_global_flag & 0x70U) != 0) {
            return report_debugger_signal(
                logger_handle,
                log_level,
                nt_global_flag_event(),
                nt_global_flag_format(),
                nt_global_flag_detail());
        }

        if (analysis_process_blacklist_check() == 0) {
            return report_debugger_signal(
                logger_handle,
                log_level,
                tooling_process_event(),
                tooling_process_format(),
                tooling_process_detail());
        }

        wchar_t environment_value[2]{};
        SetLastError(ERROR_SUCCESS);
        const DWORD environment_length = GetEnvironmentVariableW(
            ssl_key_log_environment_name(),
            environment_value,
            static_cast<DWORD>(std::size(environment_value)));
        if (environment_length != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
            SetEnvironmentVariableW(ssl_key_log_environment_name_for_clear(), nullptr);
            return report_debugger_signal(
                logger_handle,
                log_level,
                ssl_key_log_event(),
                ssl_key_log_format(),
                ssl_key_log_detail());
        }

        if (!loaded_module_names_are_clean()) {
            return report_debugger_signal(
                logger_handle,
                log_level,
                suspicious_module_event(),
                suspicious_module_format(),
                suspicious_module_detail());
        }

        if (invalid_close_handle_raised_exception()) {
            return report_debugger_signal(
                logger_handle,
                log_level,
                log_level == 0 ? invalid_handle_event() : invalid_handle_verbose_event(),
                invalid_handle_format(),
                log_level == 0 ? invalid_handle_detail() : invalid_handle_verbose_detail());
        }

        std::uintptr_t process_heap{};
        std::memcpy(&process_heap, peb + 0x30, sizeof(process_heap));
        if (process_heap != 0) {
            ULONG force_flags{};
            unsigned char flags{};
            std::memcpy(
                &flags,
                reinterpret_cast<const void*>(process_heap + 0x70),
                sizeof(flags));
            std::memcpy(
                &force_flags,
                reinterpret_cast<const void*>(process_heap + 0x74),
                sizeof(force_flags));
            if ((flags & 0x60U) != 0 || force_flags != 0) {
                return report_debugger_signal(
                    logger_handle,
                    log_level,
                    log_level == 0 ? heap_flags_event() : heap_flags_verbose_event(),
                    heap_flags_format(),
                    log_level == 0 ? heap_flags_detail() : heap_flags_verbose_detail());
            }
        }
    }
    return nullptr;
}

}
