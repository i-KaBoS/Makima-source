#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace makima::storage::registry {

struct RegistryGuardExchange final {
    std::array<std::byte, 32> primary;
    std::byte ready;
    alignas(4) std::array<std::byte, 16> secondary;
    std::array<std::byte, 3> trailer;
};

static_assert(offsetof(RegistryGuardExchange, primary) == 0x00);
static_assert(offsetof(RegistryGuardExchange, ready) == 0x20);
static_assert(offsetof(RegistryGuardExchange, secondary) == 0x24);
static_assert(offsetof(RegistryGuardExchange, trailer) == 0x34);

void initialize_registry_guard_exchange(
    RegistryGuardExchange& exchange) noexcept;

void complete_registry_protected_boundary() noexcept;

[[nodiscard]] char* allocate_code_encrypt_manual_map_failed(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_guard_shutdown_export(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_guard_init_exception_detail(
    const std::uint8_t* protected_source);

[[nodiscard]] wchar_t* allocate_quoted_executable_and_url_argument_template(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_loader_protocol_registry_path(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_loader_protocol_display_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_url_protocol_registry_value_name(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_default_icon_registry_key_name(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
[[nodiscard]] wchar_t* allocate_quoted_executable_icon_index_zero_template(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_shell_registry_key_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_open_registry_key_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_command_registry_key_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_local_edge_update_service_lock(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_makima_window_title(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t*
allocate_close_any_debugging_or_analysis_tools_before_using_the_makima_loader(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_chrome_131_windows_user_agent(
    std::int64_t protected_source);

struct ProcessStorageReference;



struct ProcessStorageReferenceVtable final {
    std::uintptr_t slot_00{};
    std::uintptr_t slot_08{};
    void (*release_dependency)(ProcessStorageReference*) noexcept{};
    std::uintptr_t slot_18{};
    void (*destroy_reference)(
        ProcessStorageReference*, std::uint32_t release_storage) noexcept{};
};

struct ProcessStorageReference final {
    ProcessStorageReferenceVtable* vtable{};
    std::uint32_t unobserved_word_08{};
    std::int32_t reference_count{};
};

static_assert(offsetof(ProcessStorageReference, reference_count) == 0x0c);


extern ProcessStorageReference* process_storage_release_dependency;


void release_process_storage_reference(ProcessStorageReference* reference) noexcept;


void release_owned_process_storage() noexcept;
void release_active_ecdh_runtime_state() noexcept;
[[nodiscard]] std::string* write_primary_guard_success_response(
    std::string* output);
[[nodiscard]] std::string* write_secondary_guard_success_response(
    std::string* output);


[[nodiscard]] std::uint64_t current_process_has_no_debug_port() noexcept;

char* integrity_capture_buffer() noexcept;
void integrity_capture_storage_release(char* buffer, std::size_t capacity) noexcept;




[[nodiscard]] void* registry_dispatch_state_address() noexcept;
[[nodiscard]] void* registry_iteration_state_address() noexcept;




using GuardShutdownCallback = void (*)();
extern GuardShutdownCallback guard_shutdown_callback;
void release_guard_backed_process_storage(char* storage) noexcept;


void stop_registry_guard_worker() noexcept;





using RegistryQueryCounter = std::int32_t (*)(std::int64_t* counter) noexcept;
using RegistrySleep = void (*)(std::uint32_t milliseconds) noexcept;
struct RegistryTelemetryWorkerRuntime final {
    void* worker_thread{};
    bool running{};
    std::uint8_t reserved[7]{};
    RegistryQueryCounter query_counter{};
    RegistrySleep sleep{};
};

static_assert(sizeof(RegistryTelemetryWorkerRuntime) == 0x20);
static_assert(offsetof(RegistryTelemetryWorkerRuntime, worker_thread) == 0x00);
static_assert(offsetof(RegistryTelemetryWorkerRuntime, running) == 0x08);
static_assert(offsetof(RegistryTelemetryWorkerRuntime, query_counter) == 0x10);
static_assert(offsetof(RegistryTelemetryWorkerRuntime, sleep) == 0x18);

[[nodiscard]] RegistryTelemetryWorkerRuntime&
registry_telemetry_worker_runtime() noexcept;
void start_registry_telemetry_worker() noexcept;
void stop_registry_telemetry_worker() noexcept;



[[nodiscard]] bool start_process_discovery_notification_worker() noexcept;
void stop_process_discovery_notification_worker() noexcept;


[[nodiscard]] std::uintptr_t run_registry_message_loop() noexcept;




[[nodiscard]] std::uint64_t create_edge_update_webview_environment(
    std::int64_t webview_owner) noexcept;



[[nodiscard]] void* resolve_dynamic_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_ascii_folded_module_and_exact_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_case_folded_library_and_verbatim_symbol(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_lowercase_module_hash_and_export_hash(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_ascii_normalized_module_and_exact_symbol(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_case_normalized_library_and_verbatim_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_folded_library_hash_and_exact_symbol_hash(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_lowercased_module_and_unmodified_export(
    const char* module_name,
    const char* export_name) noexcept;






[[nodiscard]] void* resolve_case_folded_module_and_exact_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_folded_module_and_verbatim_export(
    const char* module_name,
    const char* export_name) noexcept;



[[nodiscard]] wchar_t* allocate_localappdata_for_edge_update_cache_path(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_microsoft_edge_update_cache(
    std::int64_t protected_source);
[[nodiscard]] wchar_t*
allocate_enable_features_mswebview2enabledraggableregions_disable(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_ok_true_json_response(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_secondary_ok_true_json_response(
    const std::byte* protected_source);





[[nodiscard]] char*
allocate_check_manual_map_of_guard_dll_returned_invalid_mapping(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_guard_init(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_guard_verify_integrity(
    std::int64_t protected_source);
[[nodiscard]] char*
allocate_check_guard_init_export_not_found_in_mapped_guard_dll(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_code_encrypt_guard_init_missing(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_code_encrypt_guard_init_exception(
    std::int64_t protected_source);




[[nodiscard]] wchar_t* allocate_shcore_dll(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_get_dpi_for_monitor_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_shcore_dll_for_dpi_window(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_localappdata(
    const std::int16_t* protected_source);
[[nodiscard]] wchar_t* allocate_microsoft_edge_update_splash(
    std::int64_t protected_source);

struct ProtocolRegistration {
    std::wstring scheme;
    std::wstring display_name;
    std::wstring command;
};

[[nodiscard]] bool install_protocol_handler(const ProtocolRegistration& registration) noexcept;
[[nodiscard]] bool remove_protocol_handler(std::wstring_view scheme) noexcept;
[[nodiscard]] bool ensure_protocol_handler(
    const ProtocolRegistration& registration,
    bool enabled) noexcept;
[[nodiscard]] std::vector<std::wstring> enumerate_protocol_values(std::wstring_view scheme);
[[nodiscard]] bool read_protocol_command(std::wstring_view scheme, std::wstring& command) noexcept;

}
