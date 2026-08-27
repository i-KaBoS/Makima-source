#pragma once

#include <windows.h>

namespace makima::security::identity {

[[nodiscard]] BOOL CALLBACK capture_visible_window_for_process(
    HWND window,
    LPARAM context) noexcept;

[[nodiscard]] bool enumerate_windows_for_security_context(
    DWORD process_id,
    HWND* selected_window) noexcept;

}
