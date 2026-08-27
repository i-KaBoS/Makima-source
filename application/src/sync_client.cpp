#include "makima/application/sync_client.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <exception>

namespace makima::application {
namespace {

void append(Bytes& destination, const Bytes& source) {
    destination.insert(destination.end(), source.begin(), source.end());
}

Json parse_json_or_string(std::string_view text) {
    if (text.empty()) return nullptr;
    try {
        return Json::parse(text);
    } catch (const std::exception&) {
        return std::string{text};
    }
}

constexpr std::string_view session_not_ready_code = "E01";
constexpr std::string_view empty_request_code = "E02";
constexpr std::string_view malformed_response_code = "E03";
constexpr std::string_view response_authentication_code = "E04";
constexpr std::string_view transport_failure_code = "E05";

}

namespace shared {
bool start_authenticated_request_worker() noexcept;
}

std::uint64_t SystemClock::unix_time_ms() const {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

SyncClient::SyncClient(
    IHttpTransport& http,
    ICryptoProvider& crypto,
    IClock& clock,
    std::chrono::milliseconds timeout)
    : http_(http), crypto_(crypto), clock_(clock), codec_(crypto), timeout_(timeout) {}

void SyncClient::require_success_status(int status, std::string_view operation) {
    if (status < 200 || status >= 300)
        throw ApplicationError(std::string(transport_failure_code) + ": " +
            std::string(operation) + " failed with HTTP " + std::to_string(status));
}

void SyncClient::open(std::string hwid) {



    if (hwid.empty()) throw ApplicationError("HWID cannot be empty");
    reset_session_key_schedule(&key_schedule_);
    const std::uint64_t started_ms = clock_.unix_time_ms();
    HandshakeAttempt attempt = codec_.begin_handshake(hwid, started_ms);
    HttpResponse response = http_.post(sync_endpoint, attempt.request, timeout_);
    require_success_status(response.status, "handshake");
    if (response.body.empty()) throw ApplicationError(std::string{malformed_response_code});
    const HandshakeResult handshake = codec_.finish_handshake(attempt, response.body);

    session_key_ = handshake.session_key;
    control_session_key_.fill(0);
    hwid_ = std::move(hwid);
    next_sequence_ = 2;
    established_time_ms_ = clock_.unix_time_ms();
    server_session_id_ = handshake.server_session_id;
    server_clock_delta_seconds_ =
        static_cast<std::int64_t>(established_time_ms_ / 1000) -
        static_cast<std::int64_t>(handshake.server_time_seconds);
    session_open_ = true;
    authenticated_ = false;
}

std::string SyncClient::read_operation_text(
    std::span<const std::uint8_t> payload,
    std::size_t maximum_length) {
    if (payload.empty() || payload.front() != 1) {
        throw ApplicationError(ProtocolCodec::read_error(payload)
            .value_or("Invalid server response."));
    }
    std::size_t offset = 1;
    if (offset < payload.size() && payload[offset] == 1) ++offset;
    if (offset + 2 <= payload.size()) {
        const std::size_t length = static_cast<std::size_t>(payload[offset]) |
            (static_cast<std::size_t>(payload[offset + 1]) << 8U);
        if (length <= maximum_length && length <= payload.size() - offset - 2) {
            offset += 2;
            return std::string(payload.begin() + offset, payload.begin() + offset + length);
        }
    }
    if (payload.size() - offset > maximum_length) {
        throw ApplicationError("Invalid server response.");
    }
    return std::string(payload.begin() + offset, payload.end());
}

Json SyncClient::start_discord_authorization() {


    const Frame response = exchange(Opcode::discord_start, {});
    const std::string url = read_operation_text(response.payload, 2048);
    return Json::Object{{"success", true}, {"url", url}};
}

Json SyncClient::redeem(std::string_view key) {

    if (!authenticated_) throw ApplicationError("key redemption requires an authenticated account");
    if (key.empty()) throw ApplicationError("license key cannot be empty");
    const Frame response = exchange(Opcode::redeem, ProtocolCodec::pack_text(key));
    const std::string product = read_operation_text(response.payload, 64 * 1024);
    return Json::Object{{"success", true}, {"product", parse_json_or_string(product)}};
}

Json SyncClient::notifications(std::string_view cursor) {


    const Frame response = exchange(Opcode::notifications, ProtocolCodec::pack_text(cursor));
    const std::string body = read_operation_text(response.payload, 256 * 1024);
    Json parsed = parse_json_or_string(body);
    return parsed.is_array() ? parsed : Json{Json::Array{}};
}

Json SyncClient::probe_connection(std::string_view hwid) {



    try {
        if (!session_open_) open(std::string{hwid});
        const Frame response = exchange(Opcode::connection_probe, {});
        if (response.payload.empty() || response.payload.front() != 1) {
            throw ApplicationError(ProtocolCodec::read_error(response.payload)
                .value_or("Cannot connect to servers. Check your internet connection."));
        }
        return Json::Object{{"ok", true}, {"error", ""}};
    } catch (const std::exception& error) {
        const std::string_view detail = error.what();
        std::string message;
        if (detail.find("clock") != detail.npos || detail.find("timestamp") != detail.npos ||
            detail.find("clock_skew") != detail.npos) {
            if (server_clock_delta_seconds_ != 0) {
                constexpr char clock_message_format[] =
                    "Your Windows clock is %lld seconds out of sync with our servers. "
                    "Right-click the taskbar clock > Adjust date/time > Sync now.";
                std::array<char, 192> clock_message{};
                std::snprintf(
                    clock_message.data(), clock_message.size(), clock_message_format,
                    static_cast<long long>(std::llabs(server_clock_delta_seconds_)));
                message = clock_message.data();
            } else {
                message = "Your system clock is out of sync. Go to Settings > Time & Language "
                    "and click \"Sync now\".";
            }
        } else if (detail.find("invalid") != detail.npos ||
                   detail.find(malformed_response_code) != detail.npos) {
            message = "Invalid server response.";
        } else if (detail.find("certificate") != detail.npos) {
            message = "Connection interception detected. Remove any local proxies or "
                "network debugging tools.";
        } else {
            message = "Connection failed.";
        }
        return Json::Object{{"ok", false}, {"error", std::move(message)}};
    }
}

Frame SyncClient::exchange(Opcode opcode, std::span<const std::uint8_t> payload) {


    std::scoped_lock lock(exchange_mutex_);
    if (!session_open_) throw ApplicationError(std::string{session_not_ready_code});
    const auto sequence = next_sequence_++;
    Bytes request = codec_.pack_frame(session_key_, sequence, opcode, payload, clock_.unix_time_ms());
    if (request.empty()) throw ApplicationError(std::string{empty_request_code});
    HttpResponse response = http_.post(sync_endpoint, request, timeout_);
    require_success_status(response.status, "opcode request");
    if (response.body.empty()) throw ApplicationError(std::string{malformed_response_code});
    Frame frame;
    try {
        frame = codec_.unpack_frame(session_key_, response.body);
    } catch (const std::exception&) {
        throw ApplicationError(std::string{response_authentication_code});
    }
    if (frame.sequence != sequence) {
        throw ApplicationError(std::string{response_authentication_code});
    }
    return frame;
}

std::string SyncClient::request_control_ticket(std::string_view refresh_token) {
    if (!authenticated_) {
        throw ApplicationError("control-ticket refresh requires an authenticated account");
    }
    const Bytes request = ProtocolCodec::pack_text(refresh_token);
    const Frame response = exchange(Opcode::control_ticket, request);
    if (response.payload.empty() || response.payload.front() != 1) {
        throw ApplicationError(ProtocolCodec::read_error(response.payload)
            .value_or("control-ticket refresh was rejected"));
    }
    if (response.payload.size() < 3) {
        throw ApplicationError("control-ticket response is truncated");
    }
    const std::size_t length = static_cast<std::size_t>(response.payload[1]) |
        (static_cast<std::size_t>(response.payload[2]) << 8U);
    if (length == 0 || length > 79 || length > response.payload.size() - 3) {
        throw ApplicationError("control-ticket response length is invalid");
    }
    return std::string(response.payload.begin() + 3, response.payload.begin() + 3 + length);
}

LoginModel SyncClient::login(std::string_view email, std::string_view password) {

    authenticated_ = false;
    control_session_key_.fill(0);
    if (email.empty() || password.empty()) throw ApplicationError("email and password are required");
    Bytes body = ProtocolCodec::pack_text(email);
    append(body, ProtocolCodec::pack_text(password));
    append(body, ProtocolCodec::pack_text(hwid_));
    Frame response = exchange(Opcode::login, body);
    LoginModel model = parse_login_payload(response.payload);
    const Hash256 control_key = codec_.derive_control_session_key(session_key_);
    control_session_key_ = control_key;
    authenticated_ = true;
    return model;
}




LoginModel* coordinate_authenticated_login(
    AuthenticatedLoginOperation* operation,
    LoginModel* output,
    const char* email,
    const char* password) noexcept {
    if (output == nullptr) return nullptr;
    *output = {};
    if (operation == nullptr) return output;

    operation->error.clear();
    operation->succeeded = false;
    if (operation->client == nullptr || operation->hardware_id.empty() ||
        email == nullptr || password == nullptr) {
        operation->error = "login operation is missing required input";
        return output;
    }

    try {
        if (!operation->client->authenticated()) {
            operation->client->open(std::string{operation->hardware_id});
        }
        LoginModel login = operation->client->login(email, password);
        if (!shared::start_authenticated_request_worker()) {
            throw ApplicationError("authenticated environment probe could not be started");
        }
        if (operation->control_session != nullptr &&
            !operation->control_session->start(
                login, operation->client->control_session_key())) {
            throw ApplicationError("authenticated control session could not be started");
        }
        *output = std::move(login);
        operation->succeeded = true;
    } catch (const std::exception& error) {
        *output = {};
        operation->error = error.what()[0] == '\0' ? "Login failed." : error.what();
    } catch (...) {
        *output = {};
        operation->error = "Login failed.";
    }
    return output;
}

AuthorizedPayload SyncClient::download_authorized(
    std::string_view slug,
    std::string_view branch) {
    if (!authenticated_) throw ApplicationError("payload download requires an authenticated account");
    if (slug.empty()) throw ApplicationError("product slug cannot be empty");
    if (branch.empty()) branch = "stable";
    Bytes ticket_request = ProtocolCodec::pack_text(slug);
    append(ticket_request, ProtocolCodec::pack_text(branch));
    Frame ticket_response = exchange(Opcode::launch_ticket, ticket_request);
    LaunchTicket ticket = ProtocolCodec::read_ticket(ticket_response.payload);
    Frame payload_response = exchange(Opcode::payload, ticket.salt);

    AuthorizedPayload result;
    result.image = codec_.decrypt_payload(payload_response.payload, session_key_, ticket, hwid_);
    result.sha256 = crypto_.sha256(result.image);
    return result;
}



Bytes SyncClient::submit_security_event(
    std::string_view anonymous_event,
    std::string_view authenticated_event) {
    const auto selected_event = authenticated_ && !authenticated_event.empty()
        ? authenticated_event
        : anonymous_event;
    return submit_security_event_document(selected_event);
}





Bytes SyncClient::submit_security_event_document(
    std::string_view event_document) {
    if (!session_open_) {
        throw ApplicationError("security-event submission requires an open session");
    }
    const auto payload = std::span{
        reinterpret_cast<const std::uint8_t*>(event_document.data()),
        event_document.size()};
    return exchange(Opcode::security_event, payload).payload;
}

Bytes SyncClient::request_auxiliary_payload() {
    if (!authenticated_) throw ApplicationError("opcode 0xC0 requires an authenticated account");
    return exchange(Opcode::auxiliary_payload, {}).payload;
}

}

namespace {

std::mutex authenticated_request_client_mutex;
makima::application::SyncClient* authenticated_request_client{};

}

namespace makima::network::session {

void bind_authenticated_request_client(
    application::SyncClient* client) noexcept {
    std::scoped_lock lock{authenticated_request_client_mutex};
    authenticated_request_client = client;
}

application::SyncClient* current_authenticated_request_client() noexcept {
    std::scoped_lock lock{authenticated_request_client_mutex};
    return authenticated_request_client;
}

bool send_authenticated_request(
    const std::byte* data,
    std::size_t size) noexcept {
    if (data == nullptr || size == 0) return false;

    std::scoped_lock lock{authenticated_request_client_mutex};
    if (authenticated_request_client == nullptr) return false;

    try {
        const std::string_view request{
            reinterpret_cast<const char*>(data), size};
        (void)authenticated_request_client->submit_security_event_document(request);
        return true;
    } catch (...) {
        return false;
    }
}

}
