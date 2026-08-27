#include "makima/platform/win32_entry.hpp"

#include <windows.h>

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <utility>

namespace makima::platform {

Win32ApplicationPlatform::Win32ApplicationPlatform(
    std::wstring single_instance_name,
    InitializeCallback initialize,
    ShutdownCallback shutdown)
    : single_instance_name_(std::move(single_instance_name)),
      initialize_(std::move(initialize)),
      shutdown_(std::move(shutdown)) {
    if (single_instance_name_.empty()) {
        throw application::ApplicationError("single-instance mutex name cannot be empty");
    }
}

Win32ApplicationPlatform::~Win32ApplicationPlatform() {
    shutdown();
}

bool Win32ApplicationPlatform::acquire_single_instance() {
    if (instance_mutex_ != nullptr) {
        return true;
    }
    SetLastError(ERROR_SUCCESS);
    const auto mutex = CreateMutexW(nullptr, FALSE, single_instance_name_.c_str());
    if (mutex == nullptr) {
        throw application::ApplicationError("CreateMutexW failed for the single-instance gate");
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return false;
    }
    instance_mutex_ = mutex;
    return true;
}

void Win32ApplicationPlatform::initialize() {
    if (initialized_) {
        return;
    }
    if (initialize_) {
        initialize_();
    }
    initialized_ = true;
}

int Win32ApplicationPlatform::run_message_loop() {
    MSG message{};
    for (;;) {
        const auto result = GetMessageW(&message, nullptr, 0, 0);
        if (result == -1) {
            throw application::ApplicationError("GetMessageW failed");
        }
        if (result == 0) {
            return static_cast<int>(message.wParam);
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
}

void Win32ApplicationPlatform::shutdown() noexcept {
    if (initialized_) {
        if (shutdown_) {
            try {
                shutdown_();
            } catch (...) {
            }
        }
        initialized_ = false;
    }
    if (instance_mutex_ != nullptr) {
        CloseHandle(static_cast<HANDLE>(instance_mutex_));
        instance_mutex_ = nullptr;
    }
}

void Win32WindowService::webview_ready() {
    if (window_ != nullptr) {
        ShowWindow(window_, SW_SHOWNORMAL);
        UpdateWindow(window_);
    }
}

void Win32WindowService::expand() {
    if (window_ == nullptr) {
        return;
    }
    MONITORINFO monitor{};
    monitor.cbSize = sizeof(monitor);
    const auto handle = MonitorFromWindow(window_, MONITOR_DEFAULTTONEAREST);
    if (GetMonitorInfoW(handle, &monitor) == FALSE) {
        throw application::ApplicationError("GetMonitorInfoW failed");
    }
    const auto width = monitor.rcWork.right - monitor.rcWork.left;
    const auto height = monitor.rcWork.bottom - monitor.rcWork.top;
    if (SetWindowPos(
            window_,
            nullptr,
            monitor.rcWork.left,
            monitor.rcWork.top,
            width,
            height,
            SWP_NOACTIVATE | SWP_NOZORDER) == FALSE) {
        throw application::ApplicationError("SetWindowPos failed while expanding the window");
    }
}

void Win32WindowService::resize(unsigned width, unsigned height) {
    if (window_ == nullptr) {
        return;
    }
    if (width == 0 || height == 0 ||
        width > static_cast<unsigned>(std::numeric_limits<int>::max()) ||
        height > static_cast<unsigned>(std::numeric_limits<int>::max())) {
        throw application::ApplicationError("window dimensions are outside Win32 limits");
    }
    RECT bounds{};
    if (GetWindowRect(window_, &bounds) == FALSE ||
        SetWindowPos(
            window_,
            nullptr,
            bounds.left,
            bounds.top,
            static_cast<int>(width),
            static_cast<int>(height),
            SWP_NOACTIVATE | SWP_NOZORDER) == FALSE) {
        throw application::ApplicationError("SetWindowPos failed while resizing the window");
    }
}

void Win32WindowService::minimize() {
    if (window_ != nullptr) {
        ShowWindow(window_, SW_MINIMIZE);
    }
}

void Win32WindowService::close() {
    if (window_ != nullptr && PostMessageW(window_, WM_CLOSE, 0, 0) == FALSE) {
        throw application::ApplicationError("PostMessageW(WM_CLOSE) failed");
    }
}

int run_win32_application(application::IApplicationPlatform& platform) {
    return application::ApplicationLifecycle{platform}.run();
}

}
