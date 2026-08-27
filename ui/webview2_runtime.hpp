#pragma once

#include "makima/application/ui_host.hpp"

#include <memory>

struct ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler;

namespace makima::ui {

class WebView2Runtime final : public application::IWebViewRuntime {
public:
    WebView2Runtime();
    ~WebView2Runtime() override;
    WebView2Runtime(const WebView2Runtime&) = delete;
    WebView2Runtime& operator=(const WebView2Runtime&) = delete;

    void initialize(
        void* host_window,
        const application::IAssetProvider& assets,
        MessageHandler on_message) override;
    void post_json(std::string_view json) override;
    void resize(unsigned width, unsigned height) override;
    void shutdown() noexcept override;

private:
    friend ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*
    create_edge_update_environment_completion_handler(void* owner);

    class Impl;
    std::unique_ptr<Impl> impl_;
};





[[nodiscard]] ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler*
create_edge_update_environment_completion_handler(void* owner);

[[nodiscard]] WebView2Runtime* acquire_webview_bridge() noexcept;
void reveal_window_after_navigation(void* window) noexcept;
bool post_loader_diagnostic(
    std::string_view component,
    std::string_view operation,
    std::string_view detail) noexcept;

[[nodiscard]] std::string build_inline_document(
    const application::IAssetProvider& assets);
[[nodiscard]] std::string build_startup_document(
    const application::IAssetProvider& assets);
}
