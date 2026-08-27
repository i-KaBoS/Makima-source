#pragma once

#include "makima/application/catalog.hpp"
#include "makima/application/protocol.hpp"

#include <chrono>
#include <cstddef>
#include <mutex>

namespace makima::application {

struct HttpResponse {
    int status{};
    Headers headers;
    Bytes body;
};

class IHttpTransport {
public:
    virtual ~IHttpTransport() = default;
    virtual HttpResponse post(
        std::string_view url,
        std::span<const std::uint8_t> body,
        std::chrono::milliseconds timeout) = 0;
};

class IClock {
public:
    virtual ~IClock() = default;
    virtual std::uint64_t unix_time_ms() const = 0;
};

class SystemClock final : public IClock {
public:
    std::uint64_t unix_time_ms() const override;
};

struct AuthorizedPayload {
    Bytes image;
    Headers response_headers;
    Hash256 sha256{};
};

class IAuthorizedPayloadSource {
public:
    virtual ~IAuthorizedPayloadSource() = default;
    virtual AuthorizedPayload download_authorized(
        std::string_view slug,
        std::string_view branch) = 0;
};

class SyncClient final : public IAuthorizedPayloadSource {
public:
    SyncClient(
        IHttpTransport& http,
        ICryptoProvider& crypto,
        IClock& clock,
        std::chrono::milliseconds timeout = std::chrono::seconds(30));

    void open(std::string hwid);
    LoginModel login(std::string_view email, std::string_view password);
    Json start_discord_authorization();
    Json redeem(std::string_view key);
    Json notifications(std::string_view cursor = {});
    Json probe_connection(std::string_view hwid);
    AuthorizedPayload download_authorized(
        std::string_view slug,
        std::string_view branch) override;
    Bytes submit_security_event(
        std::string_view anonymous_event,
        std::string_view authenticated_event);
    Bytes submit_security_event_document(std::string_view event_document);
    Bytes request_auxiliary_payload();
    std::string request_control_ticket(std::string_view refresh_token);
    bool authenticated() const noexcept { return authenticated_; }
    bool connected() const noexcept { return session_open_; }
    std::string_view hwid() const noexcept { return hwid_; }
    const Hash256& control_session_key() const noexcept { return control_session_key_; }

private:
    Frame exchange(Opcode opcode, std::span<const std::uint8_t> payload);
    static void require_success_status(int status, std::string_view operation);
    static std::string read_operation_text(
        std::span<const std::uint8_t> payload,
        std::size_t maximum_length);

    IHttpTransport& http_;
    ICryptoProvider& crypto_;
    IClock& clock_;
    ProtocolCodec codec_;
    SessionKeySchedule key_schedule_{};
    std::chrono::milliseconds timeout_;
    Hash256 session_key_{};
    Hash256 control_session_key_{};
    std::string hwid_;
    std::uint64_t next_sequence_{2};
    std::uint64_t established_time_ms_{};
    std::uint64_t server_session_id_{};
    std::int64_t server_clock_delta_seconds_{};
    std::mutex exchange_mutex_;
    bool session_open_{};
    bool authenticated_{};
};

class IAuthenticatedControlSession {
public:
    virtual ~IAuthenticatedControlSession() = default;
    virtual bool start(
        const LoginModel& login,
        const Hash256& session_key) noexcept = 0;
    virtual void stop() noexcept = 0;
};

struct AuthenticatedLoginOperation {
    SyncClient* client{};
    std::string_view hardware_id;
    std::string error;
    bool succeeded{};
    IAuthenticatedControlSession* control_session{};
};

LoginModel* coordinate_authenticated_login(
    AuthenticatedLoginOperation* operation,
    LoginModel* output,
    const char* email,
    const char* password) noexcept;

}

namespace makima::network::session {

void bind_authenticated_request_client(
    application::SyncClient* client) noexcept;
[[nodiscard]] application::SyncClient* current_authenticated_request_client() noexcept;
[[nodiscard]] bool send_authenticated_request(
    const std::byte* data,
    std::size_t size) noexcept;

}
