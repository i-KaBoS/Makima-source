#include "makima/application/session_preflight.hpp"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace makima::application {
namespace {

constexpr std::array<std::string_view, 9> firmware_markers{
    "VMware", "Microsoft", "KVMKVM", "XenVMM",
    "VirtualB", "VMWARE", "VBOX", "Parallels", "QEMU",
};

constexpr std::array<std::string_view, 2> virtual_machine_registry_keys{
    "SOFTWARE\\VMware, Inc.\\VMware Tools",
    "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
};

constexpr std::array<std::wstring_view, 4> virtual_machine_driver_paths{
    L"C:\\Windows\\System32\\drivers\\vmhgfs.sys",
    L"C:\\Windows\\System32\\drivers\\vmmouse.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
    L"C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
};

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char byte) {
        return static_cast<char>(std::tolower(byte));
    });
    return value;
}

bool contains_case_insensitive(std::string_view text, std::string_view marker) {
    return lowercase(std::string{text}).find(lowercase(std::string{marker})) != std::string::npos;
}

std::string virtual_machine_vendor_reason(std::string_view marker) {
    constexpr char vendor_format[] = "VM vendor: %s";
    std::array<char, 96> value{};
    std::snprintf(value.data(), value.size(), vendor_format, std::string{marker}.c_str());
    return value.data();
}

std::string query_hardware_description() {
    constexpr char hardware_description[] = "HARDWARE\\DESCRIPTION\\System";
    constexpr char bios_value_name[] = "SystemBiosVersion";
    DWORD bytes = 0;
    if (RegGetValueA(HKEY_LOCAL_MACHINE, hardware_description, bios_value_name,
            RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &bytes) != ERROR_SUCCESS ||
        bytes == 0) {
        return {};
    }
    std::string value(bytes, '\0');
    if (RegGetValueA(HKEY_LOCAL_MACHINE, hardware_description, bios_value_name,
            RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ, nullptr, value.data(), &bytes) != ERROR_SUCCESS) {
        return {};
    }
    value.resize(bytes);
    std::replace(value.begin(), value.end(), '\0', ' ');
    return value;
}

bool registry_key_exists(std::string_view path) noexcept {
    HKEY key = nullptr;
    const LSTATUS status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE, std::string{path}.c_str(), 0, KEY_READ, &key);
    if (key != nullptr) RegCloseKey(key);
    return status == ERROR_SUCCESS;
}

std::string firmware_table_text() {
    constexpr DWORD raw_smbios = 'RSMB';
    const UINT bytes = GetSystemFirmwareTable(raw_smbios, 0, nullptr, 0);
    if (bytes == 0) return {};
    std::vector<std::uint8_t> table(bytes);
    if (GetSystemFirmwareTable(raw_smbios, 0, table.data(), bytes) != bytes) return {};
    std::string text;
    text.reserve(table.size());
    for (const std::uint8_t byte : table)
        text.push_back(byte >= 0x20 && byte < 0x7f ? static_cast<char>(byte) : ' ');
    return text;
}



[[noreturn]] void report_fatal_exception_and_terminate(
    std::uint32_t exception_code,
    const void* exception_address) noexcept {
    std::array<char, 256> report{};
    std::snprintf(
        report.data(), report.size(),
        "{\"exception_code\":\"0x%08lX\",\"address\":\"0x%llX\","
        "\"thread_id\":%lu,\"location\":\"wWinMain SEH catch\"}",
        static_cast<unsigned long>(exception_code),
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(exception_address)),
        static_cast<unsigned long>(GetCurrentThreadId()));
    OutputDebugStringA("loader.wwinmain_seh");
    OutputDebugStringA(report.data());
    TerminateProcess(GetCurrentProcess(), 0);
    std::abort();
}

LONG WINAPI fatal_exception_filter(EXCEPTION_POINTERS* exception) noexcept {
    const auto* record = exception == nullptr ? nullptr : exception->ExceptionRecord;
    report_fatal_exception_and_terminate(
        record == nullptr ? 0U : record->ExceptionCode,
        record == nullptr ? nullptr : record->ExceptionAddress);
}

}



VirtualMachineAssessment* inspect_virtual_machine_indicators(
    VirtualMachineAssessment* output) noexcept {
    if (output == nullptr) return nullptr;
    *output = {};

    try {
        const std::string bios = query_hardware_description();
        for (const auto marker : firmware_markers) {
            if (contains_case_insensitive(bios, marker)) {
                output->detected = true;
                output->reason = virtual_machine_vendor_reason(marker);
                output->evidence = "VM strings in SMBIOS firmware";
                return output;
            }
        }

        const std::string smbios = firmware_table_text();
        for (const auto marker : firmware_markers) {
            if (contains_case_insensitive(smbios, marker)) {
                output->detected = true;
                output->reason = virtual_machine_vendor_reason(marker);
                output->evidence = "VM strings in SMBIOS firmware";
                return output;
            }
        }

        for (const auto key : virtual_machine_registry_keys) {
            if (registry_key_exists(key)) {
                output->detected = true;
                output->reason = "VM registry keys found";
                output->evidence = std::string{key};
                return output;
            }
        }

        for (const auto path : virtual_machine_driver_paths) {
            if (std::filesystem::exists(path)) {
                output->detected = true;
                output->reason = "VM device drivers found";
                output->evidence.assign(path.begin(), path.end());
                return output;
            }
        }
    } catch (...) {
        *output = {};
    }
    return output;
}

StartupSecurityAssessment* inspect_startup_debug_indicators(
    StartupSecurityAssessment* output) noexcept {
    if (output == nullptr) return nullptr;
    *output = {};

    wchar_t environment_value[2]{};
    const DWORD environment_length =
        GetEnvironmentVariableW(L"SSLKEYLOGFILE", environment_value, 2);
    if (environment_length != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND) {
        SetEnvironmentVariableW(L"SSLKEYLOGFILE", nullptr);
        output->detected = true;
        output->check_id = "anti_debug.sslkeylogfile";
        output->check_json = "{\"check\":\"SSLKEYLOGFILE environment variable was set\"}";
        return output;
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &context) != FALSE &&
        (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)) {
        output->detected = true;
        output->check_id = "anti_debug.hardware_breakpoint";
        output->check_json = "{\"check\":\"DR0-DR3 contain non-zero values\"}";
        return output;
    }

    BOOL remote_debugger = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) != FALSE &&
        remote_debugger != FALSE) {
        output->detected = true;
        output->check_id = "anti_debug.debug_port";
        output->check_json =
            "{\"check\":\"NtQueryInformationProcess(ProcessDebugPort) returned non-zero\"}";
        return output;
    }

    using QueryProcess = NTSTATUS (NTAPI *)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_process = ntdll == nullptr ? nullptr : reinterpret_cast<QueryProcess>(
        GetProcAddress(ntdll, "NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION basic{};
    if (query_process != nullptr &&
        query_process(
            GetCurrentProcess(), ProcessBasicInformation,
            &basic, sizeof(basic), nullptr) >= 0 &&
        basic.PebBaseAddress != nullptr) {
        constexpr std::size_t nt_global_flag_offset = 0xbc;
        const auto* nt_global_flag = reinterpret_cast<const ULONG*>(
            reinterpret_cast<const std::byte*>(basic.PebBaseAddress) + nt_global_flag_offset);
        if ((*nt_global_flag & 0x70U) != 0) {
            output->detected = true;
            output->check_id = "anti_debug.nt_global_flag";
            output->check_json =
                "{\"check\":\"PEB.NtGlobalFlag has heap-debug bits set (0x70)\"}";
        }
    }
    return output;
}

void install_fatal_exception_boundary() noexcept {
    SetUnhandledExceptionFilter(fatal_exception_filter);
}

}
