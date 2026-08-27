#include "ui/webview2_runtime.hpp"

#include "makima/application/common.hpp"
#include "makima/application/json.hpp"
#include "platform/windows/windows.hpp"

#include <windows.h>
#include <shellapi.h>
#include <WebView2.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <mutex>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace makima::ui {
namespace {

using application::ApplicationError;

std::atomic<WebView2Runtime*> active_webview_bridge{};

using CopyModulePath = char* (*)(char*, int*, HMODULE*, std::size_t) noexcept;

struct WebViewLoaderStaticDispatch final {
    CopyModulePath copy_module_path{};
};

const WebViewLoaderStaticDispatch& webview_loader_static_dispatch() noexcept {
    static const WebViewLoaderStaticDispatch dispatch{
        &::makima::platform::windows::copy_ansi_module_file_path,
    };
    return dispatch;
}


char* allocate_compact_ready_message_fragment(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\"ready\":true";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_spaced_ready_message_fragment(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\"ready\": true";
    static_assert(sizeof(value) == 14U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

std::wstring webview_loader_path() {
    std::array<char, 0x104> executable_path{};
    int copied_length = 0;
    HMODULE executable_module = nullptr;
    const auto& dispatch = webview_loader_static_dispatch();
    if (dispatch.copy_module_path(
            executable_path.data(), &copied_length, &executable_module,
            executable_path.size()) == nullptr || copied_length <= 0) {
        return L"WebView2Loader.dll";
    }
    return std::filesystem::path{executable_path.data()}
        .replace_filename("WebView2Loader.dll")
        .wstring();
}

void pump_pending_window_messages() noexcept {
    MSG message{};
    while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

}

void reveal_window_after_navigation(void* window_handle) noexcept {
    const auto window = static_cast<HWND>(window_handle);



    SetLayeredWindowAttributes(window, 0, 0, LWA_ALPHA);
    ShowWindow(window, SW_SHOWNA);

    LARGE_INTEGER frequency{};
    LARGE_INTEGER started{};
    if (QueryPerformanceFrequency(&frequency) == FALSE || frequency.QuadPart <= 0 ||
        QueryPerformanceCounter(&started) == FALSE) {
        SetLayeredWindowAttributes(window, 0, 255, LWA_ALPHA);
        UpdateWindow(window);
        return;
    }

    for (;;) {
        LARGE_INTEGER current{};
        QueryPerformanceCounter(&current);
        const double elapsed_ms = static_cast<double>(current.QuadPart - started.QuadPart) *
            1000.0 / static_cast<double>(frequency.QuadPart);
        const double progress = std::clamp(elapsed_ms / 320.0, 0.0, 1.0);
        const double inverse = 1.0 - progress;
        const double eased = 1.0 - inverse * inverse * inverse;
        const auto alpha = static_cast<BYTE>(
            std::clamp(std::lround(255.0 * eased), 0L, 255L));
        SetLayeredWindowAttributes(window, 0, alpha, LWA_ALPHA);
        if (progress >= 1.0) {
            break;
        }
        pump_pending_window_messages();
        Sleep(8);
    }
    SetLayeredWindowAttributes(window, 0, 255, LWA_ALPHA);
    UpdateWindow(window);
}

namespace {

template <class T>
class ComPointer final {
public:
    ComPointer() = default;
    ~ComPointer() { reset(); }
    ComPointer(const ComPointer&) = delete;
    ComPointer& operator=(const ComPointer&) = delete;
    ComPointer(ComPointer&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    ComPointer& operator=(ComPointer&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = std::exchange(other.value_, nullptr);
        }
        return *this;
    }

    [[nodiscard]] T* get() const noexcept { return value_; }
    T* operator->() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }

    void attach(T* value) noexcept {
        reset();
        value_ = value;
    }

    void assign(T* value) noexcept {
        if (value != nullptr) {
            value->AddRef();
        }
        reset();
        value_ = value;
    }

    void reset() noexcept {
        if (value_ != nullptr) {
            value_->Release();
            value_ = nullptr;
        }
    }

private:
    T* value_{};
};

template <class Derived, class Interface>
class CallbackBase : public Interface {
public:
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID interface_id, void** object) override {
        if (object == nullptr) {
            return E_POINTER;
        }
        *object = nullptr;
        if (IsEqualIID(interface_id, IID_IUnknown) ||
            IsEqualIID(interface_id, Derived::interface_id())) {
            *object = static_cast<Interface*>(this);
            AddRef();
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return ++references_;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        const auto remaining = --references_;
        if (remaining == 0) {
            delete static_cast<Derived*>(this);
        }
        return remaining;
    }

protected:
    ~CallbackBase() = default;

private:
    std::atomic<ULONG> references_{1};
};

std::string asset_text(
    const application::IAssetProvider& assets,
    std::string_view path) {
    const auto asset = assets.get(path);
    if (!asset) {
        throw ApplicationError("required UI asset is missing: " + std::string{path});
    }
    return std::string(
        reinterpret_cast<const char*>(asset->content.data()),
        asset->content.size());
}

std::string base64(std::span<const std::uint8_t> input) {
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((input.size() + 2) / 3) * 4);
    for (std::size_t offset = 0; offset < input.size(); offset += 3) {
        const auto first = static_cast<std::uint32_t>(input[offset]);
        const auto second = offset + 1 < input.size() ? input[offset + 1] : 0U;
        const auto third = offset + 2 < input.size() ? input[offset + 2] : 0U;
        const auto value = (first << 16U) | (second << 8U) | third;
        result.push_back(alphabet[(value >> 18U) & 0x3fU]);
        result.push_back(alphabet[(value >> 12U) & 0x3fU]);
        result.push_back(offset + 1 < input.size() ? alphabet[(value >> 6U) & 0x3fU] : '=');
        result.push_back(offset + 2 < input.size() ? alphabet[value & 0x3fU] : '=');
    }
    return result;
}

void replace_all(std::string& text, std::string_view from, std::string_view to) {
    if (from.empty()) {
        return;
    }
    std::size_t position = 0;
    while ((position = text.find(from, position)) != std::string::npos) {
        text.replace(position, from.size(), to);
        position += to.size();
    }
}

std::wstring widen(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    if (text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw ApplicationError("WebView text exceeds Win32 conversion limits");
    }
    const auto size = static_cast<int>(text.size());
    const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), size, nullptr, 0);
    if (count <= 0) {
        throw ApplicationError("WebView text is not valid UTF-8");
    }
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), size, result.data(), count) != count) {
        throw ApplicationError("WebView UTF-8 conversion failed");
    }
    return result;
}

std::string narrow(const wchar_t* text) {
    if (text == nullptr || *text == L'\0') {
        return {};
    }
    const auto length = static_cast<int>(std::wcslen(text));
    const auto count = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, text, length, nullptr, 0, nullptr, nullptr);
    if (count <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, text, length, result.data(), count, nullptr, nullptr);
    return result;
}

void generate_runtime_identifier(wchar_t* output) noexcept;

std::wstring webview_data_directory() {
    std::wstring value(32768, L'\0');
    const auto length = GetEnvironmentVariableW(
        L"LOCALAPPDATA", value.data(), static_cast<DWORD>(value.size()));
    std::filesystem::path root;
    if (length > 0 && length < value.size()) {
        value.resize(length);
        root = value;
    } else {
        root = std::filesystem::temp_directory_path();
    }
    std::array<wchar_t, 17> identifier{};
    generate_runtime_identifier(identifier.data());
    const auto path = root / L"Makima" / L"WebView2" / identifier.data();
    std::filesystem::create_directories(path);
    return path.wstring();
}

std::wstring response_headers(std::string_view mime_type) {
    constexpr char header_format[] =
        "Content-Type: %s\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *";
    const std::string mime{mime_type};
    const int count = std::snprintf(nullptr, 0, header_format, mime.c_str());
    std::string headers(static_cast<std::size_t>(count) + 1, '\0');
    std::snprintf(headers.data(), headers.size(), header_format, mime.c_str());
    headers.resize(static_cast<std::size_t>(count));
    return widen(headers);
}


std::wstring virtual_origin_index() {
    constexpr char index_format[] = "%sindex.html";
    constexpr char origin[] = "https://edge.app/";
    constexpr std::string_view recovered_uri = "https://edge.app/index.html";
    std::array<char, 64> uri{};
    std::snprintf(uri.data(), uri.size(), index_format, origin);
    if (std::string_view{uri.data()} != recovered_uri) {
        throw ApplicationError("virtual-origin default document format mismatch");
    }
    return widen(recovered_uri);
}




void generate_runtime_identifier(wchar_t* output) noexcept {
    constexpr std::wstring_view alphabet =
        L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    LARGE_INTEGER counter{};
    QueryPerformanceCounter(&counter);
    std::uint64_t state =
        static_cast<std::uint64_t>(counter.QuadPart) ^
        static_cast<std::uint64_t>(GetCurrentProcessId()) ^
        GetTickCount64();

    for (std::size_t index = 0; index != 16; ++index) {
        output[index] = alphabet[state % alphabet.size()];
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
    }
    output[16] = L'\0';
}

ComPointer<IStream> make_asset_stream(std::span<const std::uint8_t> content) {
    ComPointer<IStream> stream;
    if (content.empty()) {
        return stream;
    }

    const auto allocation_size = static_cast<SIZE_T>(content.size());
    const auto memory = GlobalAlloc(GMEM_MOVEABLE, allocation_size);
    if (memory == nullptr) {
        return stream;
    }
    void* destination = GlobalLock(memory);
    if (destination == nullptr) {
        GlobalFree(memory);
        return stream;
    }
    std::memcpy(destination, content.data(), content.size());
    GlobalUnlock(memory);

    IStream* value = nullptr;
    if (FAILED(CreateStreamOnHGlobal(memory, TRUE, &value))) {
        GlobalFree(memory);
        return stream;
    }
    stream.attach(value);
    return stream;
}

std::string asset_path_from_uri(std::wstring_view uri) {
    constexpr std::wstring_view origin = L"https://edge.app";
    if (!uri.starts_with(origin)) {
        return {};
    }
    auto path = uri.substr(origin.size());
    if (const auto delimiter = path.find_first_of(L"?#"); delimiter != path.npos) {
        path = path.substr(0, delimiter);
    }
    if (path.empty() || path == L"/") {
        path = L"/index.html";
    }
    return narrow(std::wstring{path}.c_str());
}

}

std::string build_inline_document(const application::IAssetProvider& assets) {
    auto document = asset_text(assets, "/index.html");
    const auto stylesheet = asset_text(assets, "/app.css");
    auto script = asset_text(assets, "/app.js");
    if (const auto logo = assets.get("/logo.png")) {
        const auto logo_uri = "data:image/png;base64," + base64(logo->content);
        replace_all(script, "\"/logo.png\"", "\"" + logo_uri + "\"");
        replace_all(script, "\"logo.png\"", "\"" + logo_uri + "\"");
    }
    replace_all(script, "</script", "<\\/script");

    constexpr std::string_view stylesheet_link =
        "<link rel=\"stylesheet\" href=\"/app.css\">";
    constexpr std::string_view script_link = "<script src=\"/app.js\"></script>";
    if (document.find(stylesheet_link) == std::string::npos ||
        document.find(script_link) == std::string::npos) {
        throw ApplicationError("index.html does not contain the recovered asset links");
    }
    replace_all(document, stylesheet_link, "<style>" + stylesheet + "</style>");
    replace_all(document, script_link, "<script>" + script + "</script>");
    return document;
}

std::string build_startup_document(const application::IAssetProvider& assets) {
    auto document = asset_text(assets, "/_splash.html");
    const auto logo = assets.get("/logo.png");
    if (!logo) throw ApplicationError("missing recovered startup logo");
    replace_all(
        document,
        "LOGO_PLACEHOLDER",
        "data:image/png;base64," + base64(logo->content));
    return document;
}

class WebView2Runtime::Impl {
public:
    class StartupEnvironmentHandler final
        : public CallbackBase<StartupEnvironmentHandler,
              ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> {
    public:
        explicit StartupEnvironmentHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            HRESULT result,
            ICoreWebView2Environment* environment) override {

            return owner_.startup_environment_created(result, environment);
        }
    private:
        Impl& owner_;
    };

    class StartupControllerHandler final
        : public CallbackBase<StartupControllerHandler,
              ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> {
    public:
        explicit StartupControllerHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            HRESULT result,
            ICoreWebView2Controller* controller) override {


            return owner_.startup_controller_created(result, controller);
        }
    private:
        Impl& owner_;
    };

    class StartupMessageHandler final
        : public CallbackBase<StartupMessageHandler,
              ICoreWebView2WebMessageReceivedEventHandler> {
    public:
        explicit StartupMessageHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2WebMessageReceivedEventHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            ICoreWebView2*,
            ICoreWebView2WebMessageReceivedEventArgs* arguments) override {


            return owner_.startup_message_received(arguments);
        }
    private:
        Impl& owner_;
    };

    class MainEnvironmentHandler final
        : public CallbackBase<MainEnvironmentHandler,
              ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> {
    public:
        explicit MainEnvironmentHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            HRESULT result,
            ICoreWebView2Environment* environment) override {

            return owner_.main_environment_created(result, environment);
        }
    private:
        Impl& owner_;
    };

    class MainControllerHandler final
        : public CallbackBase<MainControllerHandler,
              ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> {
    public:
        explicit MainControllerHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2CreateCoreWebView2ControllerCompletedHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            HRESULT result,
            ICoreWebView2Controller* controller) override {


            return owner_.main_controller_created(result, controller);
        }
    private:
        Impl& owner_;
    };

    class MainMessageHandler final
        : public CallbackBase<MainMessageHandler,
              ICoreWebView2WebMessageReceivedEventHandler> {
    public:
        explicit MainMessageHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2WebMessageReceivedEventHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            ICoreWebView2*,
            ICoreWebView2WebMessageReceivedEventArgs* arguments) override {

            return owner_.main_message_received(arguments);
        }
    private:
        Impl& owner_;
    };

    class WebResourceHandler final
        : public CallbackBase<WebResourceHandler,
              ICoreWebView2WebResourceRequestedEventHandler> {
    public:
        explicit WebResourceHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2WebResourceRequestedEventHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            ICoreWebView2*,
            ICoreWebView2WebResourceRequestedEventArgs* arguments) override {


            return owner_.resource_requested(arguments);
        }
    private:
        Impl& owner_;
    };

    class NavigationCompletedHandler final
        : public CallbackBase<NavigationCompletedHandler,
              ICoreWebView2NavigationCompletedEventHandler> {
    public:
        explicit NavigationCompletedHandler(Impl& owner) noexcept : owner_(owner) {}
        static REFIID interface_id() noexcept {
            return IID_ICoreWebView2NavigationCompletedEventHandler;
        }
        HRESULT STDMETHODCALLTYPE Invoke(
            ICoreWebView2*,
            ICoreWebView2NavigationCompletedEventArgs* arguments) override {
            return owner_.navigation_completed(arguments);
        }
    private:
        Impl& owner_;
    };

    using CreateEnvironmentFunction = HRESULT(STDAPICALLTYPE*)(
        PCWSTR,
        PCWSTR,
        ICoreWebView2EnvironmentOptions*,
        ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*);

    void initialize(
        HWND window,
        const application::IAssetProvider& assets,
        application::IWebViewRuntime::MessageHandler handler) {
        shutdown();
        if (window == nullptr || !handler) {
            throw ApplicationError("WebView2 requires a host window and message handler");
        }
        const auto com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(com_result) && com_result != RPC_E_CHANGED_MODE) {
            throw ApplicationError("CoInitializeEx failed for WebView2");
        }
        com_initialized_ = SUCCEEDED(com_result);
        window_ = window;
        assets_ = &assets;
        on_message_ = std::move(handler);
        startup_document_ = widen(build_startup_document(assets));

        const std::wstring loader_path = webview_loader_path();
        loader_ = LoadLibraryW(loader_path.c_str());
        if (loader_ == nullptr) {
            shutdown();
            throw ApplicationError("WebView2Loader.dll is missing beside MakimaLoader.exe");
        }
        const auto procedure = GetProcAddress(loader_, "CreateCoreWebView2EnvironmentWithOptions");
        static_assert(sizeof(create_environment_) == sizeof(procedure));
        std::memcpy(&create_environment_, &procedure, sizeof(create_environment_));
        if (create_environment_ == nullptr) {
            shutdown();
            throw ApplicationError("WebView2Loader.dll does not export the environment factory");
        }

        data_directory_ = webview_data_directory();
        startup_complete_ = false;
        startup_passed_ = false;
        auto* completion = new StartupEnvironmentHandler{*this};
        const auto result = create_environment_(
            nullptr, data_directory_.c_str(), nullptr, completion);
        completion->Release();
        if (FAILED(result)) {
            shutdown();
            throw ApplicationError("WebView2 startup-probe environment could not be started");
        }



        while (!startup_complete_) {
            MSG message{};
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
                if (message.message == WM_QUIT) {
                    shutdown();
                    throw ApplicationError("application closed during the startup probe");
                }
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
            Sleep(1);
        }
        if (!startup_passed_) {
            shutdown();
            throw ApplicationError("the WebView startup environment check failed");
        }

        reset_startup_webview();
        auto* main_completion = new MainEnvironmentHandler{*this};
        const auto main_result = create_environment_(
            nullptr, data_directory_.c_str(), nullptr, main_completion);
        main_completion->Release();
        if (FAILED(main_result)) {
            shutdown();
            throw ApplicationError("WebView2 main environment creation could not be started");
        }
    }

    void post_json(std::string_view json) {
        if (!webview_) {
            pending_messages_.emplace_back(json);
            return;
        }
        const auto value = widen(json);
        if (FAILED(webview_->PostWebMessageAsJson(value.c_str()))) {
            throw ApplicationError("WebView2 rejected a JSON host message");
        }
    }

    void resize(unsigned width, unsigned height) noexcept {
        width_ = width;
        height_ = height;
        apply_bounds();
    }

    void shutdown() noexcept {
        navigation_worker_.request_stop();
        navigation_worker_ = {};
        if (webview_ && navigation_token_.value != 0) {
            webview_->remove_NavigationCompleted(navigation_token_);
        }
        if (webview_ && resource_token_.value != 0) {
            webview_->remove_WebResourceRequested(resource_token_);
            webview_->RemoveWebResourceRequestedFilter(
                L"https://edge.app/*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL);
        }
        if (webview_ && message_token_.value != 0) {
            webview_->remove_WebMessageReceived(message_token_);
        }
        navigation_token_ = {};
        resource_token_ = {};
        message_token_ = {};
        if (controller_) {
            controller_->Close();
        }
        webview_.reset();
        controller_.reset();
        environment_.reset();
        reset_startup_webview();
        pending_messages_.clear();
        on_message_ = {};
        startup_document_.clear();
        data_directory_.clear();
        assets_ = nullptr;
        window_ = nullptr;
        create_environment_ = nullptr;
        startup_complete_ = false;
        startup_passed_ = false;
        opacity_animation_active_ = false;
        visible_after_navigation_ = false;
        minimized_after_fade_ = false;
        if (loader_ != nullptr) {
            FreeLibrary(loader_);
            loader_ = nullptr;
        }
        if (com_initialized_) {
            CoUninitialize();
            com_initialized_ = false;
        }
    }

    HRESULT startup_environment_created(
        HRESULT result,
        ICoreWebView2Environment* environment) noexcept {
        if (FAILED(result) || environment == nullptr || window_ == nullptr) {
            startup_passed_ = false;
            startup_complete_ = true;
            return FAILED(result) ? result : E_FAIL;
        }
        startup_environment_.assign(environment);
        auto* completion = new StartupControllerHandler{*this};
        const auto create_result =
            environment->CreateCoreWebView2Controller(window_, completion);
        completion->Release();
        if (FAILED(create_result)) {
            startup_passed_ = false;
            startup_complete_ = true;
            return create_result;
        }
        return S_OK;
    }

    HRESULT main_environment_created(HRESULT result, ICoreWebView2Environment* environment) {
        if (FAILED(result) || environment == nullptr || window_ == nullptr) {
            return report_async_failure(L"Microsoft Edge WebView2 Runtime is unavailable.");
        }
        environment_.assign(environment);
        auto* completion = new MainControllerHandler{*this};
        const auto create_result = environment->CreateCoreWebView2Controller(window_, completion);
        completion->Release();
        if (FAILED(create_result)) {
            return report_async_failure(L"WebView2 could not create its window controller.");
        }
        return S_OK;
    }

    HRESULT startup_controller_created(
        HRESULT result,
        ICoreWebView2Controller* controller) noexcept {


        if (FAILED(result) || controller == nullptr) {
            startup_passed_ = false;
            startup_complete_ = true;
            return FAILED(result) ? result : E_FAIL;
        }
        startup_controller_.assign(controller);

        ComPointer<ICoreWebView2Controller2> controller2;
        ICoreWebView2Controller2* controller2_value = nullptr;
        if (SUCCEEDED(controller->QueryInterface(
                IID_ICoreWebView2Controller2,
                reinterpret_cast<void**>(&controller2_value))) &&
            controller2_value != nullptr) {
            controller2.attach(controller2_value);
            constexpr COREWEBVIEW2_COLOR startup_background{0xff, 0x05, 0x05, 0x07};
            controller2->put_DefaultBackgroundColor(startup_background);
        }

        ICoreWebView2* webview_value = nullptr;
        const auto core_result = controller->get_CoreWebView2(&webview_value);
        if (FAILED(core_result) || webview_value == nullptr) {
            startup_passed_ = false;
            startup_complete_ = true;
            return FAILED(core_result) ? core_result : E_FAIL;
        }
        startup_webview_.attach(webview_value);

        ICoreWebView2Settings* settings_value = nullptr;
        if (SUCCEEDED(startup_webview_->get_Settings(&settings_value)) &&
            settings_value != nullptr) {
            ComPointer<ICoreWebView2Settings> settings;
            settings.attach(settings_value);
            settings->put_AreDevToolsEnabled(FALSE);
            settings->put_AreDefaultContextMenusEnabled(FALSE);
            settings->put_IsStatusBarEnabled(FALSE);
        }

        RECT bounds{};
        GetClientRect(window_, &bounds);
        controller->put_Bounds(bounds);

        auto* message_handler = new StartupMessageHandler{*this};
        const auto event_result = startup_webview_->add_WebMessageReceived(
            message_handler, &startup_message_token_);
        message_handler->Release();
        if (FAILED(event_result) || FAILED(startup_webview_->NavigateToString(
                startup_document_.c_str()))) {
            startup_passed_ = false;
            startup_complete_ = true;
            return FAILED(event_result) ? event_result : E_FAIL;
        }
        return S_OK;
    }

    HRESULT main_controller_created(HRESULT result, ICoreWebView2Controller* controller) {


        if (FAILED(result) || controller == nullptr) {
            return report_async_failure(L"WebView2 controller initialization failed.");
        }
        controller_.assign(controller);

        ComPointer<ICoreWebView2Controller2> controller2;
        ICoreWebView2Controller2* controller2_value = nullptr;
        if (SUCCEEDED(controller->QueryInterface(
                IID_ICoreWebView2Controller2,
                reinterpret_cast<void**>(&controller2_value))) &&
            controller2_value != nullptr) {
            controller2.attach(controller2_value);
            constexpr COREWEBVIEW2_COLOR main_background{0xff, 0x0a, 0x0a, 0x0c};
            controller2->put_DefaultBackgroundColor(main_background);
        }
        ICoreWebView2* webview = nullptr;
        const auto core_result = controller_->get_CoreWebView2(&webview);
        if (FAILED(core_result) || webview == nullptr) {
            return report_async_failure(L"WebView2 did not return its core interface.");
        }
        webview_.attach(webview);

        ICoreWebView2Settings* settings_value = nullptr;
        if (SUCCEEDED(webview_->get_Settings(&settings_value)) && settings_value != nullptr) {
            ComPointer<ICoreWebView2Settings> settings;
            settings.attach(settings_value);
            settings->put_AreDefaultScriptDialogsEnabled(FALSE);
            settings->put_IsStatusBarEnabled(FALSE);
            settings->put_AreDevToolsEnabled(FALSE);
            settings->put_AreDefaultContextMenusEnabled(FALSE);
            settings->put_IsZoomControlEnabled(FALSE);
            settings->put_IsBuiltInErrorPageEnabled(FALSE);

            ComPointer<ICoreWebView2Settings3> settings3;
            ICoreWebView2Settings3* settings3_value = nullptr;
            if (SUCCEEDED(settings->QueryInterface(
                    IID_ICoreWebView2Settings3,
                    reinterpret_cast<void**>(&settings3_value))) &&
                settings3_value != nullptr) {
                settings3.attach(settings3_value);
                settings3->put_AreBrowserAcceleratorKeysEnabled(FALSE);
            }

            ComPointer<ICoreWebView2Settings4> settings4;
            ICoreWebView2Settings4* settings4_value = nullptr;
            if (SUCCEEDED(settings->QueryInterface(
                    IID_ICoreWebView2Settings4,
                    reinterpret_cast<void**>(&settings4_value))) &&
                settings4_value != nullptr) {
                settings4.attach(settings4_value);
                settings4->put_IsGeneralAutofillEnabled(FALSE);
                settings4->put_IsPasswordAutosaveEnabled(FALSE);
            }
        }

        auto* handler = new MainMessageHandler{*this};
        const auto event_result = webview_->add_WebMessageReceived(handler, &message_token_);
        handler->Release();
        if (FAILED(event_result)) {
            return report_async_failure(L"WebView2 message bridge initialization failed.");
        }

        if (FAILED(webview_->AddWebResourceRequestedFilter(
                L"https://edge.app/*", COREWEBVIEW2_WEB_RESOURCE_CONTEXT_ALL))) {
            return report_async_failure(L"WebView2 asset filter initialization failed.");
        }
        auto* resource_handler = new WebResourceHandler{*this};
        const auto resource_result =
            webview_->add_WebResourceRequested(resource_handler, &resource_token_);
        resource_handler->Release();
        if (FAILED(resource_result)) {
            return report_async_failure(L"WebView2 asset handler initialization failed.");
        }

        auto* navigation_handler = new NavigationCompletedHandler{*this};
        const auto navigation_result =
            webview_->add_NavigationCompleted(navigation_handler, &navigation_token_);
        navigation_handler->Release();
        if (FAILED(navigation_result)) {
            return report_async_failure(L"WebView2 navigation handler initialization failed.");
        }

        apply_bounds();
        const std::wstring index_uri = virtual_origin_index();
        if (FAILED(webview_->Navigate(index_uri.c_str()))) {
            return report_async_failure(L"WebView2 could not load the application interface.");
        }
        for (const auto& message : std::exchange(pending_messages_, {})) {
            const auto value = widen(message);
            webview_->PostWebMessageAsJson(value.c_str());
        }
        return S_OK;
    }

    HRESULT startup_message_received(
        ICoreWebView2WebMessageReceivedEventArgs* arguments) noexcept {


        if (arguments == nullptr) {
            return E_INVALIDARG;
        }
        LPWSTR value = nullptr;
        const auto result = arguments->TryGetWebMessageAsString(&value);
        if (FAILED(result) || value == nullptr) {
            return result;
        }
        const auto message = narrow(value);
        CoTaskMemFree(value);
        if (message.find("splash_ready") != std::string::npos) {
            return S_OK;
        }
        if (message.find("splash_result") != std::string::npos) {
            startup_passed_ = message.find("pass") != std::string::npos;
            startup_complete_ = true;
            return S_OK;
        }



        try {
            if (on_message_) on_message_(message);
        } catch (...) {
            post_loader_diagnostic(
                "webview", "dispatch_startup_message",
                "the startup command consumer raised an exception");
            return E_FAIL;
        }
        return S_OK;
    }

    HRESULT main_message_received(
        ICoreWebView2WebMessageReceivedEventArgs* arguments) noexcept {
        if (arguments == nullptr || window_ == nullptr) {
            return E_INVALIDARG;
        }
        LPWSTR value = nullptr;
        const auto result = arguments->TryGetWebMessageAsString(&value);
        if (FAILED(result) || value == nullptr) {
            return FAILED(result) ? result : E_FAIL;
        }




        const std::string message = narrow(value);
        CoTaskMemFree(value);
        try {
            if (on_message_ && !message.empty()) on_message_(message);
        } catch (...) {
            post_loader_diagnostic(
                "webview", "dispatch_message", "the command consumer raised an exception");
            return E_FAIL;
        }
        static const char* const compact_ready =
            allocate_compact_ready_message_fragment(
                reinterpret_cast<const std::uint8_t*>(0x1414DF628ull));
        static const char* const spaced_ready =
            allocate_spaced_ready_message_fragment(
                reinterpret_cast<const std::uint8_t*>(0x1414DF636ull));
        const bool page_is_ready =
            message.find(compact_ready) != std::string::npos ||
            message.find(spaced_ready) != std::string::npos;
        if (page_is_ready && !visible_after_navigation_.load() &&
            !opacity_animation_active_.exchange(true) &&
            !minimized_after_fade_.load()) {
            reveal_window_after_navigation(window_);
            visible_after_navigation_ = true;
            opacity_animation_active_ = false;
        }
        return S_OK;
    }

    HRESULT resource_requested(
        ICoreWebView2WebResourceRequestedEventArgs* arguments) noexcept {


        if (arguments == nullptr || assets_ == nullptr || !environment_) {
            return E_INVALIDARG;
        }

        ComPointer<ICoreWebView2WebResourceRequest> request;
        ICoreWebView2WebResourceRequest* request_value = nullptr;
        auto result = arguments->get_Request(&request_value);
        if (FAILED(result) || request_value == nullptr) {
            return FAILED(result) ? result : E_FAIL;
        }
        request.attach(request_value);

        LPWSTR uri_value = nullptr;
        result = request->get_Uri(&uri_value);
        if (FAILED(result) || uri_value == nullptr) {
            return FAILED(result) ? result : E_FAIL;
        }
        const auto path = asset_path_from_uri(uri_value);
        CoTaskMemFree(uri_value);

        const auto asset = path.empty() ? std::nullopt : assets_->get(path);
        ComPointer<IStream> content;
        std::wstring headers = L"Content-Length: 0";
        int status = 404;
        const wchar_t* reason = L"Not Found";
        if (asset) {
            content = make_asset_stream(asset->content);
            if (!asset->content.empty() && !content) {
                return E_OUTOFMEMORY;
            }
            const std::string_view mime_type = asset->mime_type.empty()
                ? "application/octet-stream"
                : std::string_view{asset->mime_type};
            headers = response_headers(mime_type);
            status = 200;
            reason = L"OK";
        }

        ICoreWebView2WebResourceResponse* response_value = nullptr;
        result = environment_->CreateWebResourceResponse(
            content.get(), status, reason, headers.c_str(), &response_value);
        if (FAILED(result) || response_value == nullptr) {
            return FAILED(result) ? result : E_FAIL;
        }
        ComPointer<ICoreWebView2WebResourceResponse> response;
        response.attach(response_value);
        return arguments->put_Response(response.get());
    }

    HRESULT navigation_completed(
        ICoreWebView2NavigationCompletedEventArgs* arguments) noexcept {
        if (arguments == nullptr) {
            return E_INVALIDARG;
        }
        BOOL succeeded = FALSE;
        const auto result = arguments->get_IsSuccess(&succeeded);
        if (FAILED(result)) {
            return result;
        }
        if (succeeded == FALSE) {
            COREWEBVIEW2_WEB_ERROR_STATUS status{};
            arguments->get_WebErrorStatus(&status);
            return report_async_failure(L"The application WebView page failed to load.");
        }

        schedule_navigation_reveal();
        return S_OK;
    }




    void schedule_navigation_reveal() {
        navigation_worker_.request_stop();
        navigation_worker_ = std::jthread([this](std::stop_token stop) {
            std::mutex delay_mutex;
            std::condition_variable_any delay;
            std::unique_lock lock(delay_mutex);
            delay.wait_for(lock, stop, std::chrono::seconds(2), [] { return false; });
            if (stop.stop_requested()) {
                return;
            }
            const HWND window = window_;
            if (window != nullptr && IsWindow(window) &&
                !opacity_animation_active_.exchange(true) &&
                !minimized_after_fade_.load()) {
                reveal_window_after_navigation(window);
                visible_after_navigation_ = true;
                minimized_after_fade_ = false;
                opacity_animation_active_ = false;
            }
        });
    }

private:
    void reset_startup_webview() noexcept {
        if (startup_webview_ && startup_message_token_.value != 0) {
            startup_webview_->remove_WebMessageReceived(startup_message_token_);
        }
        startup_message_token_ = {};
        if (startup_controller_) {
            startup_controller_->Close();
        }
        startup_webview_.reset();
        startup_controller_.reset();
        startup_environment_.reset();
    }

    HRESULT report_async_failure(const wchar_t* message) noexcept {



        constexpr wchar_t runtime_error[] =
            L"Makima Loader requires Microsoft Edge WebView2 Runtime, which is "
            L"missing or could not be loaded.\n\nClick OK to open the official ";
        (void)message;
        if (MessageBoxW(
                nullptr, runtime_error, L"Makima Loader",
                MB_OKCANCEL | MB_ICONERROR | MB_SYSTEMMODAL |
                    MB_SETFOREGROUND | MB_TOPMOST) == IDOK) {
            ShellExecuteW(
                nullptr, L"open",
                L"https://go.microsoft.com/fwlink/p/?LinkId=2124703",
                nullptr, nullptr, SW_SHOWNORMAL);
        }
        ExitProcess(1);
        return E_FAIL;
    }

    void apply_bounds() noexcept {
        if (!controller_ || window_ == nullptr) {
            return;
        }
        RECT bounds{};
        if (GetClientRect(window_, &bounds) == FALSE) {
            bounds.right = static_cast<LONG>(width_);
            bounds.bottom = static_cast<LONG>(height_);
        }
        controller_->put_Bounds(bounds);
    }

    HWND window_{};
    HMODULE loader_{};
    bool com_initialized_{};
    unsigned width_{960};
    unsigned height_{660};
    CreateEnvironmentFunction create_environment_{};
    std::wstring data_directory_;
    std::wstring startup_document_;
    bool startup_complete_{};
    bool startup_passed_{};
    const application::IAssetProvider* assets_{};
    application::IWebViewRuntime::MessageHandler on_message_;
    std::vector<std::string> pending_messages_;
    std::jthread navigation_worker_;
    std::atomic_bool opacity_animation_active_{};
    std::atomic_bool visible_after_navigation_{};
    std::atomic_bool minimized_after_fade_{};
    EventRegistrationToken startup_message_token_{};
    EventRegistrationToken message_token_{};
    EventRegistrationToken resource_token_{};
    EventRegistrationToken navigation_token_{};
    ComPointer<ICoreWebView2Environment> startup_environment_;
    ComPointer<ICoreWebView2Controller> startup_controller_;
    ComPointer<ICoreWebView2> startup_webview_;
    ComPointer<ICoreWebView2Environment> environment_;
    ComPointer<ICoreWebView2Controller> controller_;
    ComPointer<ICoreWebView2> webview_;
};

ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*
create_edge_update_environment_completion_handler(void* owner) {


    static_assert(sizeof(WebView2Runtime::Impl::MainEnvironmentHandler) == 0x18);
    auto* const implementation = static_cast<WebView2Runtime::Impl*>(owner);
    return new WebView2Runtime::Impl::MainEnvironmentHandler{*implementation};
}

WebView2Runtime::WebView2Runtime() : impl_(std::make_unique<Impl>()) {}
WebView2Runtime::~WebView2Runtime() { shutdown(); }

void WebView2Runtime::initialize(
    void* host_window,
    const application::IAssetProvider& assets,
    MessageHandler on_message) {
    impl_->initialize(static_cast<HWND>(host_window), assets, std::move(on_message));
    active_webview_bridge.store(this, std::memory_order_release);
}

void WebView2Runtime::post_json(std::string_view json) {
    impl_->post_json(json);
}

void WebView2Runtime::resize(unsigned width, unsigned height) {
    impl_->resize(width, height);
}

void WebView2Runtime::shutdown() noexcept {
    WebView2Runtime* expected = this;
    active_webview_bridge.compare_exchange_strong(
        expected, nullptr, std::memory_order_acq_rel);
    impl_->shutdown();
}



WebView2Runtime* acquire_webview_bridge() noexcept {
    return active_webview_bridge.load(std::memory_order_acquire);
}



bool post_loader_diagnostic(
    std::string_view component,
    std::string_view operation,
    std::string_view detail) noexcept {
    WebView2Runtime* bridge = acquire_webview_bridge();
    if (bridge == nullptr) return false;
    try {
        bridge->post_json(application::Json(application::Json::Object{
            {"event", "loader_diagnostic"},
            {"data", application::Json::Object{
                {"component", std::string{component}},
                {"operation", std::string{operation}},
                {"detail", std::string{detail}},
            }},
        }).dump());
        return true;
    } catch (...) {
        return false;
    }
}

}
