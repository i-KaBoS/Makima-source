#pragma once

#include <cstddef>
#include <cstdint>

#include <windows.h>
#include <bcrypt.h>

namespace makima::process::discovery {

[[nodiscard]] bool fill_discovery_nonce(
    void* context,
    void* output,
    std::size_t output_size) noexcept;

[[nodiscard]] char* allocate_create_event_w(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_kernel32_for_create_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_set_event(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_kernel32_dll(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_wait_for_single_object(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] char* allocate_kernel32_dll_for_wait_for_single_object(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_sleep_api_name(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_kernel32_for_sleep(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_enum_windows_api_name(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_user32_for_enum_windows(
    const std::byte* protected_source);

void resolve_create_event_import() noexcept;
void resolve_set_event_import() noexcept;
void resolve_wait_for_single_object_import() noexcept;
void resolve_bcrypt_generate_key_pair_import() noexcept;
void resolve_bcrypt_finalize_key_pair_import() noexcept;
void resolve_bcrypt_export_key_import() noexcept;
void resolve_bcrypt_import_key_pair_import() noexcept;
void resolve_bcrypt_secret_agreement_import() noexcept;
void resolve_bcrypt_derive_key_import() noexcept;
void resolve_bcrypt_destroy_secret_import() noexcept;

using DiscoveryWorkerCallback = void (*)(std::uintptr_t context) noexcept;




struct DiscoveryWorkerRuntime {
    bool running{true};
    void* wake_event{};
    void* release_event{};
    void* worker_thread{};
    bool dispatching{};
    DiscoveryWorkerCallback pending_callback{};
    std::uintptr_t pending_context{};
};

[[nodiscard]] DiscoveryWorkerRuntime& discovery_worker_runtime() noexcept;


[[nodiscard]] void* resolve_process_discovery_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_ascii_folded_discovery_module_export(
    const char* module_name,
    const char* export_name) noexcept;


[[nodiscard]] std::uint32_t discovery_notification_worker(void*) noexcept;



void publish_discovery_worker_notification(
    DiscoveryWorkerCallback callback,
    std::uintptr_t context) noexcept;





void enumerate_windows_or_select_target() noexcept;
[[nodiscard]] std::uint32_t find_process_id_by_image_name(
    const wchar_t* image_name) noexcept;
[[nodiscard]] std::uintptr_t wait_for_target_window(
    const wchar_t* image_name) noexcept;


[[nodiscard]] wchar_t* process_target_truncate_mode();





[[nodiscard]] bool encrypt_aes256_gcm_buffer(
    const std::byte* key,
    const std::byte* plaintext,
    std::uint32_t input_size,
    const std::byte* authenticated_data,
    std::uint32_t authenticated_data_size,
    std::byte* nonce,
    std::byte* ciphertext,
    std::byte* authentication_tag) noexcept;
[[nodiscard]] bool decrypt_aes256_gcm_buffer(
    const std::byte* key,
    const std::byte* ciphertext,
    std::uint32_t input_size,
    const std::byte* authenticated_data,
    std::uint32_t authenticated_data_size,
    const std::byte* nonce,
    const std::byte* authentication_tag,
    std::byte* plaintext) noexcept;



[[nodiscard]] std::byte* decode_protected_bytes_1402dc500(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402de500(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402e0700(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402e31a0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402e5610(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402e80a0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402ebab0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402ed7c0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402ef7c0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402f2780(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402f50c0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402f7360(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_1402f8f40(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1402fb9a0(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140302a80(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_1403087e0(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_14030af00(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14030c940(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_14030fd80(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140313660(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140316d00(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140319000(const char* source);
[[nodiscard]] std::byte* decode_protected_bytes_14031cdd0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14031f280(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_14032c290(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14032e280(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_14032f7c0(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140332c00(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140334600(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1403370e0(const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140339d00(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14033c240(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14033e500(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140341b00(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_1403443f0(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140346500(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140349a40(std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14034c180(std::int64_t source);

}
