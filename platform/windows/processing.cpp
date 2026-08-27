#include "platform/windows/windows.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <cerrno>
#include <cstring>
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

namespace makima::platform::windows {

FARPROC resolve_raise_fail_fast_exception(std::uint64_t lookup_flags) noexcept {




    (void)lookup_flags;
    HMODULE module = GetModuleHandleW(L"kernelbase.dll");
    return module == nullptr ? nullptr : GetProcAddress(module, "RaiseFailFastException");
}

FARPROC resolve_module_heap_release_routine(HMODULE module, std::string_view export_name) {
    if (module == nullptr || export_name.empty() || export_name.size() >= 256U) return nullptr;
    std::array<char, 256> export_buffer{};
    std::memcpy(export_buffer.data(), export_name.data(), export_name.size());
    export_buffer[export_name.size()] = '\0';
    return GetProcAddress(module, export_buffer.data());
}

std::uint64_t acquire_named_process_mutex(
    const char* channel_name,
    HANDLE* semaphore_out) noexcept {
    if (semaphore_out == nullptr) return ERROR_INVALID_PARAMETER;
    *semaphore_out = nullptr;
    if (channel_name == nullptr || *channel_name == '\0') return ERROR_INVALID_NAME;

    std::array<wchar_t, 0x104> local_name{};
    const int written = swprintf_s(
        local_name.data(), local_name.size(), L"Local\\SM0:%lu:%lu:%hs",
        GetCurrentProcessId(), 0x78UL, channel_name);
    if (written <= 0) return ERROR_INSUFFICIENT_BUFFER;

    HANDLE mutex = CreateMutexExW(nullptr, local_name.data(), 0, MUTEX_ALL_ACCESS);
    if (mutex == nullptr) {
        SecurityFailureContext failure{
            1U, 0U, GetLastError(), 0U, "kernel32.dll", "CreateMutexExW",
            channel_name, L"local security coordination mutex", GetCurrentThreadId()};
        std::array<wchar_t, 0x200> diagnostic{};
        (void)format_system_error_message(diagnostic.data(), diagnostic.size(), &failure);
        return failure.error_code;
    }
    const auto close_mutex = std::unique_ptr<void, decltype(&CloseHandle)>(mutex, CloseHandle);
    WaitForSecurityEventRequest wait_request{mutex, INFINITE, false, WAIT_FAILED};
    wait_request.result = WaitForSingleObjectEx(mutex, INFINITE, FALSE);
    if (wait_request.result != WAIT_OBJECT_0 && wait_request.result != WAIT_ABANDONED) {
        return wait_request.result;
    }

    HANDLE semaphore = create_or_open_named_semaphore(local_name.data(), 0, LONG_MAX);
    if (semaphore == nullptr) return GetLastError();
    *semaphore_out = semaphore;
    ReleaseMutex(mutex);
    return ERROR_SUCCESS;
}

HANDLE create_or_open_named_semaphore(std::wstring_view semaphore_name, LONG initial_count, LONG maximum_count) {
    if (semaphore_name.empty()) return nullptr;
    const std::wstring owned_name{semaphore_name};
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    using OpenSemaphoreFunction = HANDLE(WINAPI*)(DWORD, BOOL, LPCWSTR);
    using CreateSemaphoreFunction = HANDLE(WINAPI*)(
        LPSECURITY_ATTRIBUTES, LONG, LONG, LPCWSTR, DWORD, DWORD);
    const auto open_semaphore = kernel32 == nullptr ? nullptr :
        reinterpret_cast<OpenSemaphoreFunction>(GetProcAddress(kernel32, "OpenSemaphoreW"));
    const auto create_semaphore = kernel32 == nullptr ? nullptr :
        reinterpret_cast<CreateSemaphoreFunction>(GetProcAddress(kernel32, "CreateSemaphoreExW"));
    HANDLE semaphore = open_semaphore == nullptr ?
        call_open_semaphore_w(owned_name) :
        open_semaphore(SYNCHRONIZE | SEMAPHORE_MODIFY_STATE, FALSE, owned_name.c_str());
    if (semaphore != nullptr || GetLastError() != ERROR_FILE_NOT_FOUND) return semaphore;
    return create_semaphore == nullptr ?
        call_create_semaphore_ex_w(owned_name, initial_count, maximum_count) :
        create_semaphore(
            nullptr, initial_count, maximum_count, owned_name.c_str(),
            SEMAPHORE_ALL_ACCESS, 0);
}

FARPROC resolve_first_module_heap_text_release(HMODULE module, std::string_view export_name) {
    if (module == nullptr || export_name.empty()) return nullptr;
    const std::string owned_name{export_name};
    return GetProcAddress(module, owned_name.c_str());
}

}
