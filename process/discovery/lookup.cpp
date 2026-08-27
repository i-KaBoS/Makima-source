#include "process/discovery/discovery.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <array>
#include <cstring>
#include <cwchar>
#include <string_view>

namespace makima::process::discovery {
namespace {

struct WindowSearch final {
    DWORD process_id{};
    HWND window{};
};

BOOL CALLBACK capture_top_level_window(HWND window, LPARAM parameter) noexcept {
    auto& search = *reinterpret_cast<WindowSearch*>(parameter);
    if (!IsWindowVisible(window)) return TRUE;

    DWORD owner{};
    GetWindowThreadProcessId(window, &owner);
    if (owner != search.process_id) return TRUE;
    search.window = window;
    return FALSE;
}

[[nodiscard]] HWND find_window_for_process(DWORD process_id) noexcept {
    WindowSearch search{process_id, nullptr};
    EnumWindows(capture_top_level_window, reinterpret_cast<LPARAM>(&search));
    return search.window;
}

[[nodiscard]] std::wstring_view file_name_part(
    std::wstring_view path) noexcept {
    const auto separator = path.find_last_of(L'\\');
    return separator == std::wstring_view::npos
        ? path
        : path.substr(separator + 1);
}

using CreateToolhelp32SnapshotFunction = HANDLE (WINAPI*)(DWORD, DWORD);
using Process32FirstWFunction = BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using Process32NextWFunction = BOOL (WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using CloseHandleFunction = BOOL (WINAPI*)(HANDLE);

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

[[nodiscard]] CreateToolhelp32SnapshotFunction
resolve_create_toolhelp32_snapshot_provider() noexcept {
    return typed_process_export<CreateToolhelp32SnapshotFunction>(
        "kernel32.dll", "CreateToolhelp32Snapshot");
}

[[nodiscard]] Process32FirstWFunction
resolve_process32_first_w_provider() noexcept {
    return typed_process_export<Process32FirstWFunction>(
        "kernel32.dll", "Process32FirstW");
}

[[nodiscard]] Process32NextWFunction
resolve_process32_next_w_provider() noexcept {
    return typed_process_export<Process32NextWFunction>(
        "kernel32.dll", "Process32NextW");
}





[[nodiscard]] CloseHandleFunction resolve_close_handle_provider() noexcept {
    return typed_process_export<CloseHandleFunction>(
        "kernel32.dll", "CloseHandle");
}

}





void enumerate_windows_or_select_target() noexcept {
    std::array<wchar_t, MAX_PATH + 4> module_path{};
    static_cast<void>(GetModuleFileNameW(
        nullptr, module_path.data(), static_cast<DWORD>(MAX_PATH)));
    const auto image_name = file_name_part(
        std::wstring_view{module_path.data()});

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    const DWORD current_process_id = GetCurrentProcessId();
    DWORD selected_process_id{};
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == current_process_id ||
                _wcsicmp(entry.szExeFile, image_name.data()) != 0) {
                continue;
            }
            selected_process_id = entry.th32ProcessID;
            break;
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    if (selected_process_id == 0) return;
    const HWND selected = find_window_for_process(selected_process_id);
    if (selected != nullptr && IsIconic(selected)) {
        static_cast<void>(ShowWindow(selected, SW_RESTORE));
    }
    static_cast<void>(SetForegroundWindow(selected));
}








std::uint32_t find_process_id_by_image_name(
    const wchar_t* image_name) noexcept {
    const CreateToolhelp32SnapshotFunction create_snapshot =
        resolve_create_toolhelp32_snapshot_provider();
    const Process32FirstWFunction process_first =
        resolve_process32_first_w_provider();
    const Process32NextWFunction process_next =
        resolve_process32_next_w_provider();
    const CloseHandleFunction close_handle = resolve_close_handle_provider();
    if (create_snapshot == nullptr || process_first == nullptr ||
        process_next == nullptr || close_handle == nullptr) {
        return 0;
    }

    HANDLE snapshot = create_snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    DWORD process_id{};
    if (process_first(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, image_name) == 0) {
                process_id = entry.th32ProcessID;
                break;
            }
        } while (process_next(snapshot, &entry));
    }
    close_handle(snapshot);
    return process_id;
}

}
