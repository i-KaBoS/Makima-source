#pragma once

#include "makima/application/account_service.hpp"
#include "makima/application/ui_host.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace makima::platform {

struct WebSocketEndpoint {
    std::wstring host;
    std::wstring path;
    std::uint16_t port{443};
    bool secure{true};
};

enum class ControlDispatchKind {
    notification,
    refresh,
    pong,
    close,
    ignored,
};

struct ControlDispatch {
    ControlDispatchKind kind{ControlDispatchKind::ignored};
    std::string response;
    std::string event;
    std::string reason;
};

class WinHttpWebSocket final {
public:
    WinHttpWebSocket();
    ~WinHttpWebSocket();
    WinHttpWebSocket(WinHttpWebSocket&&) noexcept;
    WinHttpWebSocket& operator=(WinHttpWebSocket&&) noexcept;
    WinHttpWebSocket(const WinHttpWebSocket&) = delete;
    WinHttpWebSocket& operator=(const WinHttpWebSocket&) = delete;

    static constexpr std::uint32_t connected_status = 0x414ed401;

    [[nodiscard]] std::uint32_t connect(
        std::string_view host,
        std::string_view path) noexcept;
    [[nodiscard]] bool send_binary(std::span<const std::uint8_t> message) noexcept;
    [[nodiscard]] std::vector<std::uint8_t> receive_message();
    void close(std::uint16_t status = 1000, std::string_view reason = {}) noexcept;
    [[nodiscard]] bool connected() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

[[nodiscard]] WebSocketEndpoint loader_control_endpoint(std::string_view ticket);
bool configure_session_and_start_websocket(
    WinHttpWebSocket& socket,
    std::string_view ticket) noexcept;
[[nodiscard]] ControlDispatch dispatch_control_message(
    std::string_view message,
    std::int64_t client_time);

class ControlSession final : public application::IAuthenticatedControlSession {
public:
    ControlSession(
        application::SyncClient& sync,
        application::IWebViewBridge& webview);
    ~ControlSession() override;
    ControlSession(const ControlSession&) = delete;
    ControlSession& operator=(const ControlSession&) = delete;

    bool start(
        const application::LoginModel& login,
        const application::Hash256& session_key) noexcept override;
    void stop() noexcept override;
    [[nodiscard]] bool running() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
