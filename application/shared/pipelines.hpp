#pragma once

#include "../../payload/crypto/crypto.hpp"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace makima::application::shared {

using Octets = std::vector<std::byte>;

struct AuthenticatedTransportState final {
    void* owner{};
    const std::byte* left{};
    const std::byte* right{};
};

struct AuthenticatedRequestContext final {
    ::makima::payload::crypto::PayloadKey key{};
    ::makima::payload::crypto::PayloadKey derived_key{};
};

struct SessionRecord final {
    std::vector<std::uint32_t> words;
    std::uint32_t logical_size{};
    std::string serialized;
    bool committed{};
};

struct AuthenticatedSessionRequest final {
    ::makima::payload::crypto::PayloadKey key{};
    ::makima::payload::crypto::PayloadDigest expected_digest{};
    const std::byte* packet{};
    std::size_t packet_size{};
    const std::byte* context{};
    std::size_t context_size{};
};

struct PayloadPipelineContext final {
    ::makima::payload::crypto::PayloadKey key{};
    ::makima::payload::crypto::PayloadDigest expected_digest{};
};




struct BootstrapStatusPayload final {
    std::array<std::byte, 0x81> bytes;
};

static_assert(sizeof(BootstrapStatusPayload) == 0x81);

[[nodiscard]] void* get_application_shared_runtime_context() noexcept;
[[nodiscard]] decltype(&GetFileAttributesW) bind_get_file_attributes_w() noexcept;
void bind_winhttp_connect() noexcept;
[[nodiscard]] decltype(&WinHttpOpenRequest) bind_winhttp_open_request() noexcept;
[[nodiscard]] decltype(&WinHttpSendRequest) bind_winhttp_send_request() noexcept;
void bind_winhttp_receive_response() noexcept;
void bind_winhttp_query_data_available() noexcept;
[[nodiscard]] decltype(&WinHttpReadData) bind_winhttp_read_data() noexcept;
[[nodiscard]] decltype(&WinHttpCloseHandle) bind_winhttp_close_handle() noexcept;

[[nodiscard]] std::array<std::byte, 32>* xor_authenticated_transport_state(
    const AuthenticatedTransportState* state,
    std::array<std::byte, 32>* output) noexcept;

[[nodiscard]] bool initialize_async_security_capture() noexcept;
[[nodiscard]] bool coordinate_authenticated_request_and_derive_payload_keys(
    AuthenticatedRequestContext* context,
    const char* request) noexcept;
[[nodiscard]] bool coordinate_dwm_timing_path_and_authenticated_request() noexcept;
void report_webview_environment_creation_failure(std::int32_t hresult) noexcept;

[[nodiscard]] bool assign_authenticated_request_text(
    std::string& destination,
    const char* source,
    std::size_t length);
[[nodiscard]] std::uint64_t serialize_network_session_record(SessionRecord* record);
void build_and_dispatch_authenticated_session_request(
    AuthenticatedSessionRequest* request) noexcept;
void append_serialized_request_collection(
    std::string* output,
    const std::string_view* values,
    std::size_t value_count);
void assemble_network_session_message(
    std::string* output,
    const char* command,
    const std::vector<std::string_view>* fields);

[[nodiscard]] Octets* orchestrate_authenticated_request_and_debug_driver(
    PayloadPipelineContext* context,
    Octets* plaintext,
    char* encrypted_request,
    char* request_context) noexcept;

[[nodiscard]] bool process_authenticated_session_command(
    const ::makima::payload::crypto::PayloadKey& key,
    const ::makima::payload::crypto::PayloadDigest& expected_digest,
    std::span<const std::byte> packet,
    std::string_view request_context) noexcept;

[[nodiscard]] bool start_authenticated_request_worker() noexcept;
[[nodiscard]] const char* sync_service_origin();

[[nodiscard]] wchar_t* allocate_update_progress_document_format(
    const std::uint16_t* protected_source);

[[nodiscard]] decltype(&BCryptDestroyKey) resolve_bcrypt_destroy_key() noexcept;
[[nodiscard]] decltype(&BCryptCloseAlgorithmProvider)
resolve_bcrypt_close_algorithm_provider() noexcept;
void cleanup_ecdh_session_import_bindings(
    ::makima::payload::crypto::EcdhSession& session) noexcept;




[[nodiscard]] BootstrapStatusPayload* construct_bootstrap_status_payload(
    void* runtime_context,
    BootstrapStatusPayload* output,
    const char* message,
    const char* channel);

}
