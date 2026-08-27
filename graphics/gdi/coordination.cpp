#include "graphics/gdi/coordination.hpp"
#include "storage/registry/registry.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <windows.h>

namespace makima::graphics::gdi {

using GetDpiForMonitorFunction = HRESULT(WINAPI*)(HMONITOR, int, UINT*, UINT*);
using DwmSetWindowAttributeFunction = HRESULT(WINAPI*)(HWND, DWORD, const void*, DWORD);

static void query_monitor_dpi(HWND reference, UINT& dpi_x, UINT& dpi_y) noexcept {
    static const wchar_t* const shcore_name =
        ::makima::storage::registry::allocate_shcore_dll_for_dpi_window(
            reinterpret_cast<const std::uint16_t*>(0x1414DF0CCull));
    HMODULE shcore = LoadLibraryExW(
        shcore_name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (shcore == nullptr) return;
    const auto get_dpi = reinterpret_cast<GetDpiForMonitorFunction>(
        GetProcAddress(shcore, "GetDpiForMonitor"));
    if (get_dpi != nullptr) {
        const HMONITOR monitor = MonitorFromWindow(reference, MONITOR_DEFAULTTOPRIMARY);
        get_dpi(monitor, 0, &dpi_x, &dpi_y);
    }
    FreeLibrary(shcore);
}

bool initialize_edge_update_splash(void* application_context) noexcept {
    if (application_context == nullptr) return false;

    wchar_t local_app_data[MAX_PATH]{};
    static const wchar_t* const local_app_data_name =
        ::makima::storage::registry::allocate_localappdata(
            reinterpret_cast<const std::int16_t*>(0x1414DE66Aull));
    const DWORD length = GetEnvironmentVariableW(
        local_app_data_name,
        local_app_data,
        static_cast<DWORD>(std::size(local_app_data)));
    if (length == 0 || length >= std::size(local_app_data)) return false;

    wchar_t splash_path[MAX_PATH]{};
    static const wchar_t* const splash_suffix =
        ::makima::storage::registry::allocate_microsoft_edge_update_splash(
            0x1414DE686ll);
    if (wcscpy_s(splash_path, local_app_data) != 0 ||
        wcscat_s(splash_path, splash_suffix) != 0) {
        return false;
    }
    std::filesystem::path splash_directory{splash_path};

    UINT dpi_x = 96;
    UINT dpi_y = 96;
    static const wchar_t* const shcore_name =
        ::makima::storage::registry::allocate_shcore_dll(
            reinterpret_cast<const std::uint16_t*>(0x1414DE640ull));
    HMODULE shcore = LoadLibraryExW(
        shcore_name, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (shcore != nullptr) {
        static const char* const get_dpi_for_monitor_name =
            ::makima::storage::registry::allocate_get_dpi_for_monitor_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DE658ull));
        const auto get_dpi = reinterpret_cast<GetDpiForMonitorFunction>(
            GetProcAddress(shcore, get_dpi_for_monitor_name));
        if (get_dpi != nullptr) {
            const HMONITOR monitor = MonitorFromWindow(
                GetForegroundWindow(), MONITOR_DEFAULTTOPRIMARY);
            (void)get_dpi(monitor, 0, &dpi_x, &dpi_y);
        }
        FreeLibrary(shcore);
    }
    return !splash_directory.empty() && GetStockObject(BLACK_BRUSH) != nullptr &&
        dpi_x != 0 && dpi_y != 0;
}

std::uint32_t create_dpi_aware_splash_window(
    SplashWindowState* state,
    HINSTANCE instance) noexcept {
    if (state == nullptr || instance == nullptr) return 0;
    state->instance = instance;

    constexpr wchar_t class_name[] = L"MakimaIntegritySplashWindow";
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.lpfnWndProc = DefWindowProcW;
    window_class.hInstance = instance;
    window_class.hbrBackground = static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    window_class.lpszClassName = class_name;
    if (RegisterClassExW(&window_class) == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 0;
    }

    HWND foreground = GetForegroundWindow();
    query_monitor_dpi(foreground, state->dpi_x, state->dpi_y);
    state->width = MulDiv(960, static_cast<int>(state->dpi_x), 96);
    state->height = MulDiv(540, static_cast<int>(state->dpi_y), 96);

    RECT bounds{};
    if (foreground == nullptr || !GetWindowRect(foreground, &bounds)) {
        bounds = {0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
    }
    const int x = bounds.left + std::max(0, (bounds.right - bounds.left - state->width) / 2);
    const int y = bounds.top + std::max(0, (bounds.bottom - bounds.top - state->height) / 2);

    state->window = CreateWindowExW(
        0x000c0000,
        class_name,
        L"",
        0x80060000,
        x,
        y,
        state->width,
        state->height,
        nullptr,
        nullptr,
        instance,
        state);
    if (state->window == nullptr) return 0;

    SetLayeredWindowAttributes(state->window, 0, 0, LWA_ALPHA);
    if (HMODULE dwmapi = LoadLibraryExW(L"dwmapi.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        const auto set_attribute = reinterpret_cast<DwmSetWindowAttributeFunction>(
            GetProcAddress(dwmapi, "DwmSetWindowAttribute"));
        if (set_attribute != nullptr) {
            const BOOL enabled = TRUE;
            set_attribute(state->window, 0x14, &enabled, sizeof(enabled));
            const DWORD corner_preference = 2;
            set_attribute(state->window, 0x21, &corner_preference, sizeof(corner_preference));
        }
        FreeLibrary(dwmapi);
    }
    ShowWindow(state->window, SW_SHOWNA);
    return 1;
}

}
