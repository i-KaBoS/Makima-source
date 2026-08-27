#include "security/identity/identity.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
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

namespace makima::security::identity {

extern "C" NTSTATUS NTAPI NtImpersonateThread(
    HANDLE server_thread,
    HANDLE client_thread,
    PSECURITY_QUALITY_OF_SERVICE security_quality_of_service);

struct VisibleWindowSearch final {
    DWORD process_id{};
    DWORD reserved{};
    HWND window{};
};

static_assert(offsetof(VisibleWindowSearch, process_id) == 0);
static_assert(offsetof(VisibleWindowSearch, window) == 8);
static_assert(sizeof(VisibleWindowSearch) == 16);

template <class Procedure>
[[nodiscard]] Procedure resolve_user32_procedure(const char* name) noexcept {
    HMODULE module = GetModuleHandleW(L"user32.dll");
    if (module == nullptr) {
        module = LoadLibraryW(L"user32.dll");
    }
    const FARPROC address = module != nullptr ? GetProcAddress(module, name) : nullptr;
    Procedure procedure = nullptr;
    static_assert(sizeof(procedure) == sizeof(address));
    std::memcpy(&procedure, &address, sizeof(procedure));
    return procedure;
}


BOOL WINAPI capture_visible_window_for_process_direct(
    HWND window,
    LPARAM context) noexcept {
    auto* search = reinterpret_cast<VisibleWindowSearch*>(context);
    if (IsWindowVisible(window) == FALSE) return TRUE;

    DWORD process_id = 0;
    GetWindowThreadProcessId(window, &process_id);
    if (process_id != search->process_id) return TRUE;
    search->window = window;
    return FALSE;
}



BOOL CALLBACK capture_visible_window_for_process(HWND window, LPARAM context) noexcept {
    auto* search = reinterpret_cast<VisibleWindowSearch*>(context);

    using GetWindowThreadProcessIdProcedure = DWORD(WINAPI*)(HWND, LPDWORD);
    using IsWindowVisibleProcedure = BOOL(WINAPI*)(HWND);
    static const auto get_window_thread_process_id =
        resolve_user32_procedure<GetWindowThreadProcessIdProcedure>(
            "GetWindowThreadProcessId");
    static const auto is_window_visible =
        resolve_user32_procedure<IsWindowVisibleProcedure>("IsWindowVisible");
    if (get_window_thread_process_id == nullptr || is_window_visible == nullptr) {
        return TRUE;
    }

    DWORD process_id = 0;
    get_window_thread_process_id(window, &process_id);
    if (process_id != search->process_id || is_window_visible(window) == FALSE) {
        return TRUE;
    }
    search->window = window;
    return FALSE;
}

bool impersonate_target_window_thread(DWORD thread_id) {
    HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread_id);
    if (thread == nullptr) return false;
    const auto close_thread = std::unique_ptr<void, decltype(&CloseHandle)>(thread, CloseHandle);

    HANDLE source_token = nullptr;
    if (!OpenThreadToken(
            thread,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
            FALSE,
            &source_token)) {
        return false;
    }
    const auto close_source_token =
        std::unique_ptr<void, decltype(&CloseHandle)>(source_token, CloseHandle);
    SECURITY_QUALITY_OF_SERVICE quality{};
    quality.Length = sizeof(quality);
    quality.ImpersonationLevel = SecurityImpersonation;
    quality.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
    quality.EffectiveOnly = FALSE;
    if (NtImpersonateThread(GetCurrentThread(), thread, &quality) < 0) {
        RevertToSelf();
        return false;
    }
    return true;
}

bool enumerate_windows_for_security_context(DWORD process_id, HWND* selected_window) noexcept {
    if (selected_window == nullptr || process_id == 0) return false;
    *selected_window = nullptr;
    VisibleWindowSearch search{};
    search.process_id = process_id;
    EnumWindows(capture_visible_window_for_process, reinterpret_cast<LPARAM>(&search));
    if (search.window == nullptr) return false;
    DWORD owner_process = 0;
    const DWORD thread_id = GetWindowThreadProcessId(search.window, &owner_process);
    if (thread_id == 0 || owner_process != process_id) return false;
    if (!impersonate_target_window_thread(thread_id)) return false;
    *selected_window = search.window;
    return true;
}

}
