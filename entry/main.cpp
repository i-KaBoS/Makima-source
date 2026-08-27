#include "makima/platform/composition_root.hpp"
#include "ui/asset_loader.hpp"
#include "ui/webview2_runtime.hpp"

#include <windows.h>

#include <exception>
#include <string>

namespace {

std::wstring widen(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const auto count = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (count <= 0) {
        return L"Makima Loader failed with an unprintable error.";
    }
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), result.data(), count);
    return result;
}

}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    try {
        auto assets = makima::ui::load_embedded_assets();
        makima::ui::WebView2Runtime webview;
        return makima::platform::run_composed_win32_application(webview, assets);
    } catch (const std::exception& error) {
        const auto message = widen(error.what());
        MessageBoxW(nullptr, message.c_str(), L"Makima Loader", MB_OK | MB_ICONERROR);
        return 1;
    }
}
