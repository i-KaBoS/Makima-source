#pragma once

#include "payload/crypto/crypto.hpp"

#include <cstddef>
#include <vector>

namespace makima::payload::crypto::detail {

[[nodiscard]] char* allocate_winhttp_connect_api_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_winhttp_module_for_connect(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_winhttp_receive_response_api_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_http_receive_response_module_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_winhttp_query_available_api_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_http_query_available_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_file_attributes_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_file_attributes_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_http_open_request_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_http_open_request_module_name(
    std::int64_t protected_source,
    std::uint64_t auxiliary_tls_vector);
[[nodiscard]] char* allocate_http_send_request_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_http_send_request_module_name(
    const char* protected_source);
[[nodiscard]] char* allocate_http_read_data_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_http_read_data_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_http_close_handle_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_http_close_handle_module_name(
    std::int64_t protected_source);




struct PeImageView final {
    const std::byte* bytes{};
    std::size_t size{};
    bool valid{};
    std::byte reserved[7]{};
    const IMAGE_DOS_HEADER* dos_header{};
    const IMAGE_NT_HEADERS64* nt_headers{};
};

static_assert(offsetof(PeImageView, valid) == 0x10);
static_assert(offsetof(PeImageView, dos_header) == 0x18);
static_assert(offsetof(PeImageView, nt_headers) == 0x20);
static_assert(sizeof(PeImageView) == 0x28);

#pragma pack(push, 1)
struct MappedPeSection final {
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_data_offset{};
    std::uint32_t raw_data_size{};
    std::uint32_t characteristics{};
    std::array<std::byte, IMAGE_SIZEOF_SHORT_NAME> name{};
};
#pragma pack(pop)

static_assert(offsetof(MappedPeSection, virtual_address) == 0x00);
static_assert(offsetof(MappedPeSection, virtual_size) == 0x04);
static_assert(offsetof(MappedPeSection, raw_data_offset) == 0x08);
static_assert(offsetof(MappedPeSection, raw_data_size) == 0x0c);
static_assert(offsetof(MappedPeSection, characteristics) == 0x10);
static_assert(offsetof(MappedPeSection, name) == 0x14);
static_assert(sizeof(MappedPeSection) == 0x1c);

[[nodiscard]] PeImageView inspect_pe_image(
    const void* image_bytes,
    std::size_t image_size) noexcept;
[[nodiscard]] std::uint32_t pe_virtual_image_size(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint64_t pe_preferred_image_base(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint32_t pe_entry_point_rva(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint32_t pe_header_copy_size(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint64_t pe_stack_reserve_size(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint64_t pe_stack_commit_size(
    const PeImageView& image) noexcept;
[[nodiscard]] std::uint16_t pe_section_count(
    const PeImageView& image) noexcept;
void read_pe_section(
    const PeImageView& image,
    MappedPeSection& destination,
    int index) noexcept;

void compute_hmac_sha256(
    const std::byte* key,
    std::size_t key_size,
    const std::byte* input,
    std::size_t input_size,
    std::byte* digest) noexcept;

void resize_owned_storage(
    std::vector<std::byte>& storage,
    std::size_t size,
    const std::byte& fill);
void release_active_ecdh_runtime_state() noexcept;

[[nodiscard]] char* allocate_shell_folder_path_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_shell_folder_path_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_create_hash_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_create_hash_module_name(
    const std::uint8_t* protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_bcrypt_hash_data_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_hash_data_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_finish_hash_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_finish_hash_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_destroy_hash_api_name(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_bcrypt_destroy_hash_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_decrypt_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_decrypt_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_close_provider_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_close_provider_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bcrypt_destroy_key_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bcrypt_destroy_key_module_name(
    const std::uint8_t* protected_source);



[[nodiscard]] char* allocate_discord_login_failure(std::int64_t protected_source);
[[nodiscard]] char* allocate_login_invalid_server_response(std::int64_t protected_source);
[[nodiscard]] char* allocate_sync_invalid_server_response(std::int64_t protected_source);
[[nodiscard]] char* allocate_clock_skew_guidance(std::int64_t protected_source);
[[nodiscard]] char* allocate_clock_skew_code(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_websocket_protocol_label(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_websocket_transport_name(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_detection_state_token(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_subscription_required_message(std::int64_t protected_source);
[[nodiscard]] char* allocate_no_payload_code(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_branch_has_no_payload_message(std::int64_t protected_source, std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_session_creation_failed_message(std::int64_t protected_source);
[[nodiscard]] char* allocate_invalid_session_response_message(std::int64_t protected_source);
[[nodiscard]] char* allocate_secure_session_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_dma_dependency_download_failure(std::int64_t protected_source);
[[nodiscard]] char* allocate_payload_product_name(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_resource_fetch_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_resource_download_progress_text(std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_payload_resource_host(const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_payload_resource_request_path(const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_encrypted_payload_fetch_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_encrypted_payload_download_progress_text(std::int64_t protected_source);
[[nodiscard]] char* allocate_banned_status_token(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_account_banned_message(std::int64_t protected_source);
[[nodiscard]] char* allocate_primary_payload_download_failure(std::int64_t protected_source);
[[nodiscard]] char* allocate_secondary_payload_download_failure(std::int64_t protected_source, std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_payload_decryption_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_payload_decryption_progress_text(std::int64_t protected_source, std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_payload_derivation_label(std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_payload_resource_filename_suffix(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_hardware_id_field_name(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_retry_payload_download_failure(std::int64_t protected_source);
[[nodiscard]] char* allocate_encryption_derivation_label(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_authentication_derivation_label(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bootstrap_stable_release_channel(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_mapping_payload_download_failure(std::int64_t protected_source);
[[nodiscard]] char* allocate_injection_payload_download_failure(std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_auth_mapping_object_name(const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_target_process_image_name(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel_setup_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_initialization_progress_text(std::int64_t protected_source);
[[nodiscard]] char* allocate_timestamp_without_timezone_format(std::int64_t protected_source);
[[nodiscard]] char* allocate_string_passthrough_format(const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_target_loading_progress_title(std::int64_t protected_source);
[[nodiscard]] char* allocate_injection_progress_text(std::int64_t protected_source);
[[nodiscard]] char* allocate_injection_failure_format(std::int64_t protected_source);
[[nodiscard]] char* allocate_target_load_failure_message(std::int64_t protected_source);
[[nodiscard]] char* allocate_control_session_label(const std::uint8_t* protected_source);



[[nodiscard]] const char* discord_login_failure();
[[nodiscard]] const char* login_invalid_server_response();
[[nodiscard]] const char* sync_invalid_server_response();
[[nodiscard]] const char* clock_skew_guidance();
[[nodiscard]] const char* clock_skew_code();
[[nodiscard]] const char* websocket_protocol_label();
[[nodiscard]] const char* websocket_transport_name();
[[nodiscard]] const char* detection_state_token();
[[nodiscard]] const char* subscription_required_message();
[[nodiscard]] const char* no_payload_code();
[[nodiscard]] const char* branch_has_no_payload_message();
[[nodiscard]] const char* session_creation_failed_message();
[[nodiscard]] const char* invalid_session_response_message();
[[nodiscard]] const char* secure_session_progress_title();
[[nodiscard]] const char* connecting_progress_text();
[[nodiscard]] const char* dma_dependency_download_failure();
[[nodiscard]] const char* payload_product_name();
[[nodiscard]] const char* resource_fetch_progress_title();
[[nodiscard]] const char* resource_download_progress_text();
[[nodiscard]] const wchar_t* payload_resource_host();
[[nodiscard]] const wchar_t* payload_resource_request_path();
[[nodiscard]] const wchar_t* http_get_method();
[[nodiscard]] const char* encrypted_payload_fetch_progress_title();
[[nodiscard]] const char* encrypted_payload_download_progress_text();
[[nodiscard]] const char* banned_status_token();
[[nodiscard]] const char* account_banned_message();
[[nodiscard]] const char* primary_payload_download_failure();
[[nodiscard]] const char* secondary_payload_download_failure();
[[nodiscard]] const char* payload_decryption_progress_title();
[[nodiscard]] const char* payload_decryption_progress_text();
[[nodiscard]] const char* payload_derivation_label();
[[nodiscard]] const char* hardware_id_field_name();
[[nodiscard]] const char* alternate_derivation_label();
[[nodiscard]] const char* retry_payload_download_failure();
[[nodiscard]] const char* mapping_payload_download_failure();
[[nodiscard]] const char* injection_payload_download_failure();
[[nodiscard]] const wchar_t* auth_mapping_object_name();
[[nodiscard]] const char* target_process_image_name();
[[nodiscard]] const char* kernel_setup_progress_title();
[[nodiscard]] const char* initialization_progress_text();
[[nodiscard]] const char* timestamp_without_timezone_format();
[[nodiscard]] const char* string_passthrough_format();
[[nodiscard]] const char* target_loading_progress_title();
[[nodiscard]] const char* injection_progress_text();
[[nodiscard]] const char* injection_failure_format();
[[nodiscard]] const char* target_load_failure_message();
[[nodiscard]] const char* control_session_label();
[[nodiscard]] const char* payload_download_failure_status_record();
[[nodiscard]] const char* target_load_failure_status_record();




[[nodiscard]] char* allocate_existing_process_invalid_arguments_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_existing_process_invalid_image_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_target_process_not_found_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_existing_process_api_resolution_error(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_target_process_open_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_primary_payload_role_identifier(
    const std::uint8_t* protected_source);



[[nodiscard]] char* allocate_connection_failure_message(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_active_account_state(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_paused_account_state(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_undetected_account_state(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_updating_account_state(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_stable_release_channel(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_not_logged_in_message(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_not_connected_message(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_inactive_subscription_status(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_server_connection_failure_message(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bootstrap_status_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bootstrap_pending_json_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bootstrap_success_json_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bootstrap_error_json_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bootstrap_message_json_prefix(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_bootstrap_json_object_terminator(
    const std::uint8_t* protected_source);



[[nodiscard]] std::uint64_t map_payload_into_suspended_host(
    char* error_buffer,
    const void* payload,
    std::size_t payload_size,
    const char* relative_host_image) noexcept;
[[nodiscard]] std::uint64_t map_payload_with_remote_loader(
    char* error_buffer,
    HANDLE process,
    const void* payload,
    std::size_t payload_size) noexcept;
[[nodiscard]] char* allocate_suspended_host_invalid_arguments_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_suspended_host_invalid_image_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_suspended_host_api_resolution_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_suspended_host_creation_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_suspended_host_remote_allocation_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_remote_loader_local_api_resolution_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_remote_virtual_memory_allocation_error(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_remote_loader_local_allocation_error(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_remote_loader_kernel_module_name(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_remote_loader_native_module_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_runtime_function_table_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_remote_runtime_function_table_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_remote_loader_parameter_allocation_error(
    std::int64_t protected_source);

}
