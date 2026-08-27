#include "process/discovery/discovery.hpp"
#include "security/identity/identity.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstring>
#include <cwchar>

namespace makima::process::discovery {
namespace {

struct WindowSearch final {
    DWORD process_id{};
    HWND window{};
};

static_assert(offsetof(WindowSearch, process_id) == 0);
static_assert(offsetof(WindowSearch, window) == 8);
static_assert(sizeof(WindowSearch) == 16);

[[nodiscard]] DWORD lookup_process_id(const wchar_t* image_name) noexcept {
    return static_cast<DWORD>(find_process_id_by_image_name(image_name));
}

using SleepFunction = void (WINAPI*)(DWORD);
using EnumWindowsFunction = BOOL (WINAPI*)(WNDENUMPROC, LPARAM);

template <typename Function>
[[nodiscard]] Function typed_process_export(
    const char* module_name,
    const char* export_name) noexcept {
    void* const address = resolve_process_discovery_export(
        module_name, export_name);
    Function function{};
    static_assert(sizeof(function) == sizeof(address));
    std::memcpy(&function, &address, sizeof(function));
    return function;
}

template <typename Function>
[[nodiscard]] Function typed_ascii_folded_export(
    const char* module_name,
    const char* export_name) noexcept {
    void* const address = resolve_ascii_folded_discovery_module_export(
        module_name, export_name);
    Function function{};
    static_assert(sizeof(function) == sizeof(address));
    std::memcpy(&function, &address, sizeof(function));
    return function;
}

}







std::uintptr_t wait_for_target_window(const wchar_t* image_name) noexcept {
    static const char* const sleep_api_name = allocate_sleep_api_name(
        reinterpret_cast<const std::byte*>(0x1414D9E1Cull));
    static const char* const kernel32_name = allocate_kernel32_for_sleep(
        reinterpret_cast<const std::byte*>(0x1414D9E23ull));
    const SleepFunction sleep_function = typed_process_export<SleepFunction>(
        kernel32_name, sleep_api_name);

    static const char* const enum_windows_api_name =
        allocate_enum_windows_api_name(
            reinterpret_cast<const std::byte*>(0x1414D9E31ull));
    static const char* const user32_name = allocate_user32_for_enum_windows(
        reinterpret_cast<const std::byte*>(0x1414D9E3Eull));
    const EnumWindowsFunction enum_windows_function =
        typed_ascii_folded_export<EnumWindowsFunction>(
            user32_name, enum_windows_api_name);

    if (sleep_function == nullptr || enum_windows_function == nullptr) {
        return 0;
    }

    constexpr DWORD retry_delay_ms = 500;
    constexpr unsigned attempt_count = 240;
    for (unsigned attempt = 0; attempt < attempt_count; ++attempt) {
        const DWORD process_id = lookup_process_id(image_name);
        if (process_id != 0) {
            WindowSearch search{process_id, nullptr};
            enum_windows_function(
                ::makima::security::identity::capture_visible_window_for_process,
                reinterpret_cast<LPARAM>(&search));
            if (search.window != nullptr) {
                return reinterpret_cast<std::uintptr_t>(search.window);
            }
        }
        sleep_function(retry_delay_ms);
    }
    return 0;
}

}
