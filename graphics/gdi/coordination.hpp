#pragma once

#include <cstdint>
#include <windows.h>

namespace makima::graphics::gdi {

struct SplashWindowState final {
    HINSTANCE instance{};
    HWND window{};
    UINT dpi_x{96};
    UINT dpi_y{96};
    int width{};
    int height{};
};

[[nodiscard]] bool initialize_edge_update_splash(
    void* application_context) noexcept;
[[nodiscard]] std::uint32_t create_dpi_aware_splash_window(
    SplashWindowState* state,
    HINSTANCE instance) noexcept;

}
