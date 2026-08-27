#pragma once

#include "makima/application/application.hpp"
#include "makima/application/command_dispatcher.hpp"
#include "makima/application/events.hpp"

#include <functional>
#include <memory>
#include <optional>

namespace makima::application {

struct UiAsset {
    std::string mime_type;
    Bytes content;
};

class IAssetProvider {
public:
    virtual ~IAssetProvider() = default;
    virtual std::optional<UiAsset> get(std::string_view path) const = 0;
};

class MemoryAssetProvider final : public IAssetProvider {
public:
    void add(std::string path, std::string mime_type, Bytes content);
    std::optional<UiAsset> get(std::string_view path) const override;

private:
    std::map<std::string, UiAsset, std::less<>> assets_;
};

struct ResourceAsset {
    std::string path;
    unsigned resource_id{};
    std::wstring resource_type;
    std::string mime_type;
};

class Win32ResourceAssetProvider final : public IAssetProvider {
public:
    explicit Win32ResourceAssetProvider(void* module_handle = nullptr);
    void add(ResourceAsset asset);
    std::optional<UiAsset> get(std::string_view path) const override;

private:
    void* module_handle_{};
    std::map<std::string, ResourceAsset, std::less<>> assets_;
};

class IWebViewRuntime {
public:
    using MessageHandler = std::function<void(std::string_view)>;
    virtual ~IWebViewRuntime() = default;
    virtual void initialize(
        void* host_window,
        const IAssetProvider& assets,
        MessageHandler on_message) = 0;
    virtual void post_json(std::string_view json) = 0;
    virtual void resize(unsigned width, unsigned height) = 0;
    virtual void shutdown() noexcept = 0;
};

class WebViewEventSink final : public IEventSink {
public:
    explicit WebViewEventSink(IWebViewBridge& bridge) : bridge_(bridge) {}
    void publish(std::string_view event, const Json& data) override;
    void publish_serialized(std::string_view document) override;

private:
    IWebViewBridge& bridge_;
};

class Win32UiHost final : public IApplicationPlatform, public IWindowService, public IWebViewBridge {
public:
    Win32UiHost(IWebViewRuntime& runtime, const IAssetProvider& assets, std::wstring title = L"Makima");
    ~Win32UiHost();
    Win32UiHost(const Win32UiHost&) = delete;
    Win32UiHost& operator=(const Win32UiHost&) = delete;

    void set_message_handler(IWebViewRuntime::MessageHandler handler);
    bool acquire_single_instance() override;
    void initialize() override;
    int run_message_loop() override;
    void shutdown() noexcept override;

    void webview_ready() override;
    void expand() override;
    void resize(unsigned width, unsigned height) override;
    void minimize() override;
    void close() override;
    void post_json(std::string_view json) override;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

int run_win32_application_shell(
    IWebViewRuntime& runtime,
    const IAssetProvider& assets,
    ICommandTarget& commands);

}
