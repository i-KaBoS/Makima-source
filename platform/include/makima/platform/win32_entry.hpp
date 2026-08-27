#pragma once

#include "makima/application/application.hpp"

#include <windows.h>

#include <functional>
#include <string>

namespace makima::platform {

class Win32ApplicationPlatform final : public application::IApplicationPlatform {
public:
    using InitializeCallback = std::function<void()>;
    using ShutdownCallback = std::function<void()>;

    Win32ApplicationPlatform(
        std::wstring single_instance_name,
        InitializeCallback initialize = {},
        ShutdownCallback shutdown = {});
    ~Win32ApplicationPlatform() override;

    bool acquire_single_instance() override;
    void initialize() override;
    int run_message_loop() override;
    void shutdown() noexcept override;

private:
    std::wstring single_instance_name_;
    InitializeCallback initialize_;
    ShutdownCallback shutdown_;
    void* instance_mutex_{};
    bool initialized_{};
};

class Win32WindowService final : public application::IWindowService {
public:
    explicit Win32WindowService(HWND window) noexcept : window_(window) {}

    void webview_ready() override;
    void expand() override;
    void resize(unsigned width, unsigned height) override;
    void minimize() override;
    void close() override;

private:
    HWND window_{};
};

int run_win32_application(application::IApplicationPlatform& platform);

}
