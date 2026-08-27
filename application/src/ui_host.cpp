#include "makima/application/ui_host.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <new>
#include <string>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <dwmapi.h>
#include <windows.h>
#endif

namespace makima::application {

#ifdef _WIN32
namespace {

constexpr UINT webview_dispatch_message = WM_USER + 0xc8;
constexpr DWORD layered_application_window = WS_EX_LAYERED | WS_EX_APPWINDOW;
constexpr DWORD resizable_borderless_window = WS_POPUP | WS_MINIMIZEBOX | WS_THICKFRAME;

void pump_pending_window_messages() noexcept {
    MSG message{};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

void set_window_alpha(HWND window, BYTE alpha) noexcept {
    SetLayeredWindowAttributes(window, 0, alpha, LWA_ALPHA);
}

template <class AlphaAtProgress>
void animate_window_alpha(
    HWND window,
    double duration_ms,
    AlphaAtProgress&& alpha_at_progress) noexcept {
    LARGE_INTEGER frequency{};
    LARGE_INTEGER started{};
    if (QueryPerformanceFrequency(&frequency) == FALSE || frequency.QuadPart <= 0 ||
        QueryPerformanceCounter(&started) == FALSE) {
        set_window_alpha(window, alpha_at_progress(1.0));
        return;
    }

    for (;;) {
        LARGE_INTEGER current{};
        QueryPerformanceCounter(&current);
        const double elapsed_ms = static_cast<double>(current.QuadPart - started.QuadPart) *
            1000.0 / static_cast<double>(frequency.QuadPart);
        const double progress = std::clamp(elapsed_ms / duration_ms, 0.0, 1.0);
        set_window_alpha(window, alpha_at_progress(progress));
        if (progress >= 1.0) {
            break;
        }
        pump_pending_window_messages();
        Sleep(8);
    }
}

BYTE fade_out_alpha(double progress) noexcept {
    const double eased = 1.0 - progress * progress * progress;
    return static_cast<BYTE>(std::clamp(std::lround(255.0 * eased), 0L, 255L));
}



void fade_and_minimize(
    HWND window,
    bool& animation_active,
    bool& minimized_after_fade) noexcept {
    if (window == nullptr || animation_active) return;
    animation_active = true;
    animate_window_alpha(window, 240.0, fade_out_alpha);
    set_window_alpha(window, 0);
    animation_active = false;
    minimized_after_fade = true;
    ShowWindow(window, SW_MINIMIZE);
}



void fade_and_close(HWND window, bool& animation_active) noexcept {
    if (window == nullptr || animation_active) return;
    animation_active = true;
    animate_window_alpha(window, 240.0, fade_out_alpha);
    set_window_alpha(window, 0);
    animation_active = false;
    PostMessageW(window, WM_CLOSE, 0, 0);
}


char* allocate_ui_get_dpi_for_monitor_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "GetDpiForMonitor";
    static_assert(sizeof(value) == 17U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

float monitor_dpi_scale(HMONITOR monitor) noexcept {
    using GetDpiForMonitorFunction = HRESULT(WINAPI*)(HMONITOR, int, UINT*, UINT*);
    UINT dpi_x = 96;
    UINT dpi_y = 96;
    HMODULE shcore = LoadLibraryW(L"shcore.dll");
    if (shcore != nullptr) {
        static const char* const export_name =
            allocate_ui_get_dpi_for_monitor_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DF0E4ull));
        const auto get_dpi = reinterpret_cast<GetDpiForMonitorFunction>(
            GetProcAddress(shcore, export_name));
        if (get_dpi != nullptr) {
            get_dpi(monitor, 0, &dpi_x, &dpi_y);
        }
        FreeLibrary(shcore);
    }
    return static_cast<float>(dpi_x) / 96.0F;
}

std::string utf8_from_owned_wide_message(wchar_t* message) {
    if (message == nullptr) {
        return {};
    }
    const int length = static_cast<int>(std::wcslen(message));
    const int bytes = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, message, length, nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) {
        return {};
    }
    std::string value(static_cast<std::size_t>(bytes), '\0');
    WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, message, length, value.data(), bytes, nullptr, nullptr);
    return value;
}

std::wstring wide_from_utf8(std::string_view message) {
    if (message.empty()) return {};
    const int length = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, message.data(),
        static_cast<int>(message.size()), nullptr, 0);
    if (length <= 0) return {};
    std::wstring value(static_cast<std::size_t>(length), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, message.data(),
            static_cast<int>(message.size()), value.data(), length) != length) {
        return {};
    }
    return value;
}





void animate_window_to(HWND window, unsigned width, unsigned height, DWORD frame_delay_ms) {
    RECT current{};
    RECT work_area{};
    if (GetWindowRect(window, &current) == FALSE ||
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &work_area, 0) == FALSE) {
        SetWindowPos(
            window,
            nullptr,
            0,
            0,
            static_cast<int>(width),
            static_cast<int>(height),
            SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        return;
    }

    constexpr int frame_count = 21;
    const int start_x = current.left;
    const int start_y = current.top;
    const int start_width = current.right - current.left;
    const int start_height = current.bottom - current.top;
    const int target_x = static_cast<int>(work_area.left) + std::max(
        0, (static_cast<int>(work_area.right - work_area.left) - static_cast<int>(width)) / 2);
    const int target_y = static_cast<int>(work_area.top) + std::max(
        0, (static_cast<int>(work_area.bottom - work_area.top) - static_cast<int>(height)) / 2);

    const auto interpolate = [](int from, int to, double progress) {
        return from + static_cast<int>(std::lround((to - from) * progress));
    };
    for (int frame = 1; frame <= frame_count; ++frame) {
        const double t = static_cast<double>(frame) / frame_count;
        const double inverse = 1.0 - t;
        const double eased = 1.0 - inverse * inverse * inverse;
        SetWindowPos(
            window,
            nullptr,
            interpolate(start_x, target_x, eased),
            interpolate(start_y, target_y, eased),
            interpolate(start_width, static_cast<int>(width), eased),
            interpolate(start_height, static_cast<int>(height), eased),
            SWP_NOZORDER | SWP_NOACTIVATE);
        Sleep(frame_delay_ms);
    }
}

}
#endif

void MemoryAssetProvider::add(std::string path, std::string mime_type, Bytes content) {
    if (path.empty() || path.front() != '/') path.insert(path.begin(), '/');
    assets_.insert_or_assign(std::move(path), UiAsset{std::move(mime_type), std::move(content)});
}

std::optional<UiAsset> MemoryAssetProvider::get(std::string_view path) const {
    const auto it = assets_.find(path);
    return it == assets_.end() ? std::nullopt : std::optional<UiAsset>(it->second);
}

Win32ResourceAssetProvider::Win32ResourceAssetProvider(void* module_handle)
    : module_handle_(module_handle) {
#ifdef _WIN32
    if (!module_handle_) module_handle_ = GetModuleHandleW(nullptr);
#endif
}

void Win32ResourceAssetProvider::add(ResourceAsset asset) {
    if (asset.path.empty() || asset.path.front() != '/') asset.path.insert(asset.path.begin(), '/');
    assets_.insert_or_assign(asset.path, std::move(asset));
}

std::optional<UiAsset> Win32ResourceAssetProvider::get(std::string_view path) const {
    const auto it = assets_.find(path);
    if (it == assets_.end()) return std::nullopt;
#ifdef _WIN32
    const HMODULE module = static_cast<HMODULE>(module_handle_);
    const HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(it->second.resource_id),
        it->second.resource_type.c_str());
    if (!resource) return std::nullopt;
    const DWORD size = SizeofResource(module, resource);
    const HGLOBAL loaded = LoadResource(module, resource);
    const void* address = loaded ? LockResource(loaded) : nullptr;
    if (!address || size == 0) return std::nullopt;
    const auto* first = static_cast<const std::uint8_t*>(address);
    return UiAsset{it->second.mime_type, Bytes(first, first + size)};
#else
    return std::nullopt;
#endif
}

void WebViewEventSink::publish(std::string_view event, const Json& data) {
    bridge_.post_json(Json(Json::Object{{"event", std::string(event)}, {"data", data}}).dump());
}

void WebViewEventSink::publish_serialized(std::string_view document) {
    bridge_.post_json(document);
}

class Win32UiHost::Impl {
public:
    Impl(IWebViewRuntime& runtime, const IAssetProvider& assets, std::wstring title)
        : runtime(runtime), assets(assets), title(std::move(title)) {}

    IWebViewRuntime& runtime;
    const IAssetProvider& assets;
    std::wstring title;
    IWebViewRuntime::MessageHandler on_message;
#ifdef _WIN32
    HWND window{};
    HANDLE mutex{};
    HINSTANCE instance{};
    bool opacity_animation_active{};
    bool visible_after_navigation{};
    bool minimized_after_fade{};
    static constexpr wchar_t class_name[] = L"MakimaApplicationWindow";

    static LRESULT CALLBACK window_procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {

        Impl* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
            self = static_cast<Impl*>(create->lpCreateParams);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            self->window = window;
        }
        if (self) {
            if (message == WM_GETMINMAXINFO) {
                auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
                limits->ptMinTrackSize = POINT{720, 520};
                return 0;
            }
            if (message == WM_NCCALCSIZE) {
                return 0;
            }
            if (message == WM_NCHITTEST) {
                RECT bounds{};
                if (GetWindowRect(window, &bounds) != FALSE) {
                    constexpr LONG border = 6;
                    const LONG x = static_cast<short>(LOWORD(lparam));
                    const LONG y = static_cast<short>(HIWORD(lparam));
                    const bool left = x >= bounds.left && x < bounds.left + border;
                    const bool right = x < bounds.right && x >= bounds.right - border;
                    const bool top = y >= bounds.top && y < bounds.top + border;
                    const bool bottom = y < bounds.bottom && y >= bounds.bottom - border;
                    if (top && left) return HTTOPLEFT;
                    if (top && right) return HTTOPRIGHT;
                    if (bottom && left) return HTBOTTOMLEFT;
                    if (bottom && right) return HTBOTTOMRIGHT;
                    if (left) return HTLEFT;
                    if (right) return HTRIGHT;
                    if (top) return HTTOP;
                    if (bottom) return HTBOTTOM;
                }
                return HTCLIENT;
            }
            if (message == webview_dispatch_message) {


                auto* posted = reinterpret_cast<wchar_t*>(lparam);
                if (posted != nullptr) {
                    const auto value = utf8_from_owned_wide_message(posted);
                    std::free(posted);
                    if (!value.empty()) self->runtime.post_json(value);
                }
                return 0;
            }
            if (message == WM_SIZE && wparam != SIZE_MINIMIZED) {
                const unsigned width = static_cast<unsigned>(LOWORD(lparam));
                const unsigned height = static_cast<unsigned>(HIWORD(lparam));
                self->runtime.resize(width, height);
                return 0;
            }
            if (message == WM_CLOSE) {
                DestroyWindow(window);
                return 0;
            }
            if (message == WM_DESTROY) {
                self->window = nullptr;
                PostQuitMessage(0);
                return 0;
            }
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }
#endif
};

Win32UiHost::Win32UiHost(IWebViewRuntime& runtime, const IAssetProvider& assets, std::wstring title)
    : impl_(std::make_unique<Impl>(runtime, assets, std::move(title))) {}

Win32UiHost::~Win32UiHost() { shutdown(); }

void Win32UiHost::set_message_handler(IWebViewRuntime::MessageHandler handler) {
    impl_->on_message = std::move(handler);
}

bool Win32UiHost::acquire_single_instance() {
#ifdef _WIN32
    if (impl_->mutex) return true;
    impl_->mutex = CreateMutexW(nullptr, FALSE, L"Local\\Makima.Loader.v3");
    if (!impl_->mutex) throw ApplicationError("cannot create the single-instance mutex");
    return GetLastError() != ERROR_ALREADY_EXISTS;
#else
    return true;
#endif
}

void Win32UiHost::initialize() {
    if (!impl_->on_message) throw ApplicationError("WebView message handler is not configured");
#ifdef _WIN32
    impl_->instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.hInstance = impl_->instance;
    window_class.lpfnWndProc = &Impl::window_procedure;
    window_class.lpszClassName = Impl::class_name;
    window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    window_class.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    if (!RegisterClassExW(&window_class) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS)
        throw ApplicationError("cannot register the application window class");


    POINT cursor{};
    GetCursorPos(&cursor);
    const HMONITOR monitor = MonitorFromPoint(cursor, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitor_info{sizeof(monitor_info)};
    GetMonitorInfoW(monitor, &monitor_info);
    const float dpi_scale = monitor_dpi_scale(monitor);
    const int width = static_cast<int>(std::lround(960.0F * dpi_scale));
    const int height = static_cast<int>(std::lround(660.0F * dpi_scale));
    const int left = monitor_info.rcWork.left +
        ((monitor_info.rcWork.right - monitor_info.rcWork.left) - width) / 2;
    const int top = monitor_info.rcWork.top +
        ((monitor_info.rcWork.bottom - monitor_info.rcWork.top) - height) / 2;
    impl_->window = CreateWindowExW(layered_application_window,
        Impl::class_name, impl_->title.c_str(), resizable_borderless_window,
        left, top, width, height,
        nullptr, nullptr, impl_->instance, impl_.get());
    if (!impl_->window) throw ApplicationError("cannot create the application window");
    set_window_alpha(impl_->window, 0);
    const BOOL dark_mode = TRUE;
    DwmSetWindowAttribute(impl_->window, 0x14, &dark_mode, sizeof(dark_mode));
    const DWORD rounded_corners = 2;
    DwmSetWindowAttribute(
        impl_->window, 0x21, &rounded_corners, sizeof(rounded_corners));
    impl_->runtime.initialize(impl_->window, impl_->assets, impl_->on_message);
    ShowWindow(impl_->window, SW_SHOWNA);
#else
    throw ApplicationError("Win32 UI host is only available on Windows");
#endif
}

int Win32UiHost::run_message_loop() {
#ifdef _WIN32
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return static_cast<int>(message.wParam);
#else
    return 0;
#endif
}

void Win32UiHost::shutdown() noexcept {
    if (!impl_) return;
    impl_->runtime.shutdown();
#ifdef _WIN32
    if (impl_->window) { DestroyWindow(impl_->window); impl_->window = nullptr; }
    if (impl_->mutex) { CloseHandle(impl_->mutex); impl_->mutex = nullptr; }
#endif
}

void Win32UiHost::webview_ready() {
#ifdef _WIN32
    if (impl_->window) ShowWindow(impl_->window, SW_SHOW);
#endif
}

void Win32UiHost::expand() {
#ifdef _WIN32
    if (!impl_->window) throw ApplicationError("application window is not initialized");
    animate_window_to(impl_->window, 960, 660, 12);
#else
    resize(960, 660);
#endif
}

void Win32UiHost::resize(unsigned width, unsigned height) {
    width = std::clamp(width, 320U, 3840U);
    height = std::clamp(height, 240U, 2160U);
#ifdef _WIN32
    if (!impl_->window) throw ApplicationError("application window is not initialized");
    animate_window_to(impl_->window, width, height, 10);
#else
    (void)width; (void)height;
#endif
}

void Win32UiHost::minimize() {

#ifdef _WIN32
    fade_and_minimize(
        impl_->window, impl_->opacity_animation_active, impl_->minimized_after_fade);
#endif
}

void Win32UiHost::close() {

#ifdef _WIN32
    fade_and_close(impl_->window, impl_->opacity_animation_active);
#endif
}

void Win32UiHost::post_json(std::string_view json) {


#ifdef _WIN32
    if (impl_->window != nullptr) {
        const std::wstring value = wide_from_utf8(json);
        wchar_t* posted = _wcsdup(value.c_str());
        if (posted == nullptr) throw ApplicationError("cannot allocate WebView event message");
        if (PostMessageW(
                impl_->window, webview_dispatch_message, 0,
                reinterpret_cast<LPARAM>(posted)) == FALSE) {
            std::free(posted);
            throw ApplicationError("cannot post WebView event message");
        }
        return;
    }
#endif
    impl_->runtime.post_json(json);
}

int run_win32_application_shell(
    IWebViewRuntime& runtime,
    const IAssetProvider& assets,
    ICommandTarget& commands) {
    Win32UiHost host(runtime, assets);
    WebViewCommandDispatcher dispatcher(commands, host);
    host.set_message_handler([&](std::string_view message) { dispatcher.receive(message); });
    return ApplicationLifecycle(host).run();
}

}
