#include "makima/platform/control_session.hpp"

#include "makima/application/common.hpp"
#include "makima/application/session_wire.hpp"
#include "makima/application/runtime_libraries.hpp"
#include "makima/application/winhttp_certificate.hpp"
#include "payload/crypto/crypto.hpp"

#include <windows.h>
#include <winhttp.h>
#include <process.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <limits>
#include <thread>
#include <utility>

namespace makima::platform {
namespace {

[[noreturn]] void fail(std::string_view operation) {
    throw application::ApplicationError(
        std::string(operation) + " failed with Windows error " +
        std::to_string(GetLastError()));
}

std::wstring widen_ascii(std::string_view text) {
    return std::wstring(text.begin(), text.end());
}

std::string_view strip_control_scheme(std::string_view host, bool& secure) noexcept {
    constexpr std::string_view https_prefix = "https://";
    constexpr std::string_view http_prefix = "http://";
    if (host.starts_with(https_prefix)) {
        secure = true;
        return host.substr(https_prefix.size());
    }
    if (host.starts_with(http_prefix)) {
        secure = false;
        return host.substr(http_prefix.size());
    }
    return host;
}

std::string percent_encode(std::string_view text) {
    constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    for (const unsigned char value : text) {
        if ((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') || value == '-' || value == '_' ||
            value == '.' || value == '~') {
            result.push_back(static_cast<char>(value));
        } else {
            result.push_back('%');
            result.push_back(digits[value >> 4U]);
            result.push_back(digits[value & 0x0fU]);
        }
    }
    return result;
}

}

struct WinHttpWebSocket::State {
    HINTERNET session{};
    HINTERNET connection{};
    HINTERNET socket{};

    ~State() {
        if (socket != nullptr) {
            WinHttpWebSocketClose(socket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, nullptr, 0);
            WinHttpCloseHandle(socket);
        }
        if (connection != nullptr) WinHttpCloseHandle(connection);
        if (session != nullptr) WinHttpCloseHandle(session);
    }
};

WinHttpWebSocket::WinHttpWebSocket() : state_(std::make_unique<State>()) {}
WinHttpWebSocket::~WinHttpWebSocket() = default;
WinHttpWebSocket::WinHttpWebSocket(WinHttpWebSocket&&) noexcept = default;
WinHttpWebSocket& WinHttpWebSocket::operator=(WinHttpWebSocket&&) noexcept = default;

std::uint32_t WinHttpWebSocket::connect(
    std::string_view host,
    std::string_view path) noexcept {


    try {
    if (host.empty() || path.empty()) return 0;
    bool secure = true;
    host = strip_control_scheme(host, secure);
    if (host.empty()) return 0;
    const WebSocketEndpoint endpoint{
        .host = widen_ascii(host),
        .path = widen_ascii(path),
        .port = secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT,
        .secure = secure,
    };
    const auto& api = application::runtime_entry_points();
    close();
    state_ = std::make_unique<State>();
    constexpr wchar_t browser_user_agent[] =
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    state_->session = api.winhttp_open(
        browser_user_agent,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (state_->session == nullptr) fail("WinHttpOpen");
    state_->connection = api.winhttp_connect(
        state_->session,
        endpoint.host.c_str(),
        endpoint.port,
        0);
    if (state_->connection == nullptr) fail("WinHttpConnect");
    const DWORD flags = endpoint.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = api.winhttp_open_request(
        state_->connection,
        L"GET",
        endpoint.path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);
    if (request == nullptr) fail("WinHttpOpenRequest");
    const auto close_request = [&] { api.winhttp_close_handle(request); };
    if (api.winhttp_set_option(request, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, nullptr, 0) == FALSE) {
        close_request();
        fail("WinHttpSetOption(WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET)");
    }
    if (api.winhttp_send_request(
            request,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0) == FALSE ||
        api.winhttp_receive_response(request, nullptr) == FALSE) {
        close_request();
        fail("WebSocket HTTP upgrade");
    }
    if (endpoint.secure) {
        if (!application::verify_winhttp_server_certificate(request, host)) {
            close_request();
            fail("server certificate validation");
        }
    }
    state_->socket = api.websocket_complete_upgrade(request, 0);
    close_request();
    if (state_->socket == nullptr) fail("WinHttpWebSocketCompleteUpgrade");
    return connected_status;
    } catch (...) {
        close();
        return 0;
    }
}

bool WinHttpWebSocket::send_binary(std::span<const std::uint8_t> message) noexcept {

    if (!connected() || message.size() > std::numeric_limits<DWORD>::max()) return false;
    const auto& api = application::runtime_entry_points();
    const auto status = api.websocket_send(
        state_->socket,
        WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
        const_cast<std::uint8_t*>(message.data()),
        static_cast<DWORD>(message.size()));
    if (status != ERROR_SUCCESS) {
        return false;
    }
    return true;
}

std::vector<std::uint8_t> WinHttpWebSocket::receive_message() {


    if (!connected()) throw application::ApplicationError("WebSocket is not connected");
    std::vector<std::uint8_t> message;
    std::array<std::uint8_t, 16 * 1024> buffer{};
    for (;;) {
        DWORD received = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE type{};
        const auto& api = application::runtime_entry_points();
        const auto status = api.websocket_receive(
            state_->socket,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &received,
            &type);
        if (status != ERROR_SUCCESS) {
            SetLastError(status);
            fail("WinHttpWebSocketReceive");
        }
        if (type == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            close();
            return {};
        }
        message.insert(message.end(), buffer.begin(), buffer.begin() + received);
        if (type == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
            type == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            return message;
        }
    }
}

void WinHttpWebSocket::close(std::uint16_t status, std::string_view reason) noexcept {


    if (state_ && state_->socket != nullptr) {
        WinHttpWebSocketClose(
            state_->socket,
            status,
            const_cast<char*>(reason.data()),
            static_cast<DWORD>(reason.size()));
        WinHttpCloseHandle(state_->socket);
        state_->socket = nullptr;
    }
    if (state_ && state_->connection != nullptr) {
        WinHttpCloseHandle(state_->connection);
        state_->connection = nullptr;
    }
    if (state_ && state_->session != nullptr) {
        WinHttpCloseHandle(state_->session);
        state_->session = nullptr;
    }
}

bool WinHttpWebSocket::connected() const noexcept {
    return state_ && state_->socket != nullptr;
}

WebSocketEndpoint loader_control_endpoint(std::string_view ticket) {
    if (ticket.empty()) {
        throw application::ApplicationError("control-session ticket cannot be empty");
    }
    constexpr char ticket_path_format[] = "/api/v3/loader/session-ws?ticket=%s";
    const std::string encoded_ticket = percent_encode(ticket);
    const int path_size = std::snprintf(nullptr, 0, ticket_path_format, encoded_ticket.c_str());
    if (path_size < 0) {
        throw application::ApplicationError("control-session path formatting failed");
    }
    std::string path(static_cast<std::size_t>(path_size) + 1, '\0');
    std::snprintf(path.data(), path.size(), ticket_path_format, encoded_ticket.c_str());
    path.resize(static_cast<std::size_t>(path_size));
    return {
        .host = L"direct.makima.rip",
        .path = widen_ascii(path),
        .port = 443,
        .secure = true,
    };
}



bool configure_session_and_start_websocket(
    WinHttpWebSocket& socket,
    std::string_view ticket) noexcept {


    try {
        const WebSocketEndpoint endpoint = loader_control_endpoint(ticket);
        const std::string host(endpoint.host.begin(), endpoint.host.end());
        const std::string path(endpoint.path.begin(), endpoint.path.end());
        return socket.connect(host, path) == WinHttpWebSocket::connected_status;
    } catch (...) {
        socket.close();
        return false;
    }
}



ControlDispatch dispatch_control_message(
    std::string_view message,
    std::int64_t client_time) {
    using application::ControlMessageType;
    switch (application::classify_control_message(message)) {
    case ControlMessageType::notification:
        return {
            ControlDispatchKind::notification,
            {},
            application::serialize_notification_event(message),
            {},
        };
    case ControlMessageType::refresh:
        return {
            ControlDispatchKind::refresh,
            {},
            std::string{application::refresh_session_event()},
            {},
        };
    case ControlMessageType::ping:
        return {
            ControlDispatchKind::pong,
            application::serialize_pong(client_time),
            {},
            {},
        };
    case ControlMessageType::kill:
        return {
            ControlDispatchKind::close,
            {},
            std::string{application::control_session_kill_event()},
            std::string{application::control_session_kill_reason()},
        };
    case ControlMessageType::unknown:
        return {};
    }
    return {};
}

struct ControlSession::State {
    State(application::SyncClient& sync_client, application::IWebViewBridge& bridge)
        : sync(sync_client), webview(bridge) {}

    application::SyncClient& sync;
    application::IWebViewBridge& webview;
    WinHttpWebSocket socket;
    HANDLE worker{};
    unsigned worker_id{};
    std::mutex lifecycle;
    std::atomic_bool active{};
    std::atomic_bool stop_requested{};
    std::string ticket;
    std::string refresh_token;
    application::Hash256 session_key{};

    bool wait_before_reconnect() const noexcept {
        for (unsigned tenth = 0; tenth < 20 && !stop_requested.load(); ++tenth) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        return !stop_requested.load();
    }





    static unsigned __stdcall thread_entry(void* context) noexcept {
        auto* state = static_cast<State*>(context);
        state->run();
        return 0;
    }

    void run() noexcept {
        payload::crypto::PayloadKey payload_key{};
        std::memcpy(payload_key.data(), session_key.data(), session_key.size());

        while (!stop_requested.load(std::memory_order_acquire)) {
            if (!configure_session_and_start_websocket(socket, ticket)) {
                if (!wait_before_reconnect()) break;
                try {
                    if (!refresh_token.empty()) {
                        ticket = sync.request_control_ticket(refresh_token);
                    }
                } catch (...) {
                    continue;
                }
                continue;
            }

            bool reconnect = true;
            try {
                while (!stop_requested.load(std::memory_order_acquire) && socket.connected()) {
                    const auto encrypted = socket.receive_message();
                    if (encrypted.empty()) break;

                    std::vector<std::byte> plaintext;
                    payload::crypto::decrypt_gcm_payload_packet(
                        plaintext,
                        payload_key,
                        reinterpret_cast<const std::byte*>(encrypted.data()),
                        encrypted.size());
                    if (plaintext.empty()) break;

                    const std::string message(
                        reinterpret_cast<const char*>(plaintext.data()),
                        plaintext.size());
                    const auto now = static_cast<std::int64_t>(
                        std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::system_clock::now().time_since_epoch()).count());
                    const ControlDispatch dispatch = dispatch_control_message(message, now);
                    if (!dispatch.event.empty()) {
                        webview.post_json(dispatch.event);
                    }
                    if (!dispatch.response.empty()) {
                        const auto* first = reinterpret_cast<const std::uint8_t*>(
                            dispatch.response.data());
                        if (!socket.send_binary({first, dispatch.response.size()})) break;
                    }
                    if (dispatch.kind == ControlDispatchKind::close) {
                        socket.close(1000, dispatch.reason);
                        reconnect = false;
                        break;
                    }
                    if (dispatch.kind == ControlDispatchKind::refresh) {



                        socket.close();
                        break;
                    }
                }
            } catch (...) {


            }
            socket.close();
            if (!reconnect || stop_requested.load(std::memory_order_acquire) ||
                !wait_before_reconnect()) {
                break;
            }
            try {
                if (!refresh_token.empty()) {
                    ticket = sync.request_control_ticket(refresh_token);
                }
            } catch (...) {


            }
        }
        socket.close();
        active.store(false, std::memory_order_release);
    }
};

ControlSession::ControlSession(
    application::SyncClient& sync,
    application::IWebViewBridge& webview)
    : state_(std::make_unique<State>(sync, webview)) {}

ControlSession::~ControlSession() { stop(); }

bool ControlSession::start(
    const application::LoginModel& login,
    const application::Hash256& session_key) noexcept {
    stop();
    if (login.control_ticket.empty() ||
        std::all_of(session_key.begin(), session_key.end(),
            [](std::uint8_t byte) { return byte == 0; })) {
        return false;
    }
    try {
        std::scoped_lock lock(state_->lifecycle);
        state_->ticket = login.control_ticket;
        state_->refresh_token = login.control_refresh_token;
        state_->session_key = session_key;
        state_->stop_requested.store(false, std::memory_order_release);
        state_->active.store(true, std::memory_order_release);
        const auto worker = _beginthreadex(
            nullptr, 0, &State::thread_entry, state_.get(), 0, &state_->worker_id);
        if (worker == 0 || state_->worker_id == 0) {
            if (worker != 0) CloseHandle(reinterpret_cast<HANDLE>(worker));
            state_->active.store(false, std::memory_order_release);
            state_->worker_id = 0;
            return false;
        }
        state_->worker = reinterpret_cast<HANDLE>(worker);
        return true;
    } catch (...) {
        state_->active.store(false, std::memory_order_release);
        return false;
    }
}

void ControlSession::stop() noexcept {
    if (!state_) return;
    HANDLE worker = nullptr;
    {
        std::scoped_lock lock(state_->lifecycle);
        state_->stop_requested.store(true, std::memory_order_release);
        if (state_->worker != nullptr) {
            state_->socket.close();
            worker = std::exchange(state_->worker, nullptr);
            state_->worker_id = 0;
        }
        state_->active.store(false, std::memory_order_release);
    }
    if (worker != nullptr) {
        WaitForSingleObject(worker, INFINITE);
        CloseHandle(worker);
    }
}

bool ControlSession::running() const noexcept {
    return state_ && state_->active.load(std::memory_order_acquire);
}

}
