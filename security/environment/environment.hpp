#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <objbase.h>
#include <dxgi.h>
#include <d3d11.h>
#include <setupapi.h>
#include <hidsdi.h>
#include <hidpi.h>

namespace makima::security::environment {

using GetCurrentProcessFunction = HANDLE(WINAPI*)();

extern GetCurrentProcessFunction get_current_process_binding;
void bind_get_current_process() noexcept;

void increment_registered_callback_counter() noexcept;
void decrement_registered_callback_counter() noexcept;

void append_json_escaped_text(std::string* output, const char* input);
void append_json_string_property(
    std::string* output,
    const char* key,
    const char* value,
    char* first_property_state);
void append_json_integer_property(
    std::string* output,
    const char* key,
    std::int64_t value,
    char* first_property_state);
void append_json_boolean_property(
    std::string* output,
    const char* key,
    bool value,
    char* first_property_state);
[[nodiscard]] bool query_cpu_registry_details(
    char* processor_name,
    std::size_t processor_name_capacity,
    DWORD* frequency) noexcept;
[[nodiscard]] std::string normalize_inventory_identifier(std::string_view value);
[[nodiscard]] bool locate_internet_cache_directory(
    wchar_t* destination,
    std::size_t capacity) noexcept;
void format_cache_record_filename(
    wchar_t* destination,
    std::size_t capacity) noexcept;
[[nodiscard]] bool read_first_cache_record(
    const wchar_t* directory,
    void* output,
    std::uint32_t output_capacity,
    std::uint32_t* bytes_read) noexcept;
[[nodiscard]] bool validate_cache_record(
    std::span<const std::byte> record) noexcept;
void release_inventory_scratch(std::vector<std::byte>& scratch) noexcept;
[[nodiscard]] std::string collect_host_environment_inventory();

[[nodiscard]] wchar_t* allocate_system_informer_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_b_sentinel_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_process_explorer_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_reclass_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_scylla_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_fiddler_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_toolkit_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_proxyman_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_reqable_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_analyzer_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_debugger_pro_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_debugger_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_bracket_sentinel_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_charles_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_burp_suite_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_echo_mirage_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_wireshark_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_tshark_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_dumpcap_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_rawcap_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_smsniff_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_network_miner_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_windump_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_equals_sentinel_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_api_monitor_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_rohitab_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_winapi_override_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_spy_studio_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_wpe_pro_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_xenos_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_extreme_injector_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_gh_injector_process_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_debugger_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_winapi_override_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_spy_studio_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_echo_mirage_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_fiddler_core_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_titanium_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_http_toolkit_module_token(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_hardware_breakpoint_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_hardware_breakpoint_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hardware_breakpoint_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_global_flag_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_nt_global_flag_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_global_flag_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_tooling_process_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_tooling_process_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_tooling_process_event(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_ssl_key_log_environment_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_ssl_key_log_environment_name_for_clear(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_ssl_key_log_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_ssl_key_log_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ssl_key_log_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_suspicious_module_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_suspicious_module_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_suspicious_module_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_invalid_handle_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_invalid_handle_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_invalid_handle_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_heap_flags_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_heap_flags_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_heap_flags_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_debugger_verbose_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_debugger_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_invalid_handle_verbose_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_invalid_handle_verbose_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_heap_flags_verbose_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_heap_flags_verbose_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timing_anomaly_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timing_anomaly_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bad_parent_process_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bad_parent_process_event(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_module_scan_cheat_engine_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_module_scan_speedhack_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_module_scan_dbk64_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_module_scan_dbk32_token(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_module_scan_api_monitor_token(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_nt_query_information_process_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_set_information_thread_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_close_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_get_context_thread_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_query_system_information_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_peb_being_debugged_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_peb_debug_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_peb_being_debugged_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_port_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_process_debug_port_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_port_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_flags_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_process_debug_flags_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_flags_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_object_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_process_debug_object_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_debug_object_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_debugger_present_detail(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_percent_s_remote_debugger_present_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_debugger_present_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_get_process_id_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unauthorized_mapping_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_thread_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_remote_thread_blocked_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_rwx_thread_start_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_rwx_thread_start_blocked_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_rwx_text_protection_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_blocked_protect_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_external_suspend_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_blocked_suspend_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_thread_suspend_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_suspect_suspend_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_text_crc_mismatch_event(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_virtualbox_hypervisor_signature(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_parallels_hypervisor_signature(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_bhyve_hypervisor_signature(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_qemu_hypervisor_signature(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_reg_open_key_ex_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_reg_close_key_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_advapi32_for_reg_open_key_ex_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_advapi32_for_reg_close_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_reg_query_value_ex_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_advapi32_for_reg_query_value_ex_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_global_memory_status_ex_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_global_memory_status_ex(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_content_app_ex_cache_path_format(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_internet_cache_path_format(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_create_directory_w_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_create_directory_w(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_cache_record_filename_format(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_cache_record_search_pattern(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_find_first_file_w_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_find_first_file_w(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_cache_record_child_path_format(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_find_next_file_w_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_find_next_file_w(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_find_close_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_find_close(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_cache_record_search_pattern_for_reader(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_cache_record_child_path_format_for_reader(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_json_quote_escape(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_backslash_escape(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_newline_escape(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_carriage_return_escape(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_tab_escape(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_unicode_escape_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_comma_for_string(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_colon_for_string(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_comma_for_integer(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_signed_integer_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_colon_for_integer(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_sse2_architecture_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_comma_for_boolean(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_property_colon_for_boolean(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_true_literal(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_false_literal(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hard_disk_classification_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_get_system_time_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_get_system_time(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_co_initialize_ex_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ole32_for_co_initialize_ex(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_co_initialize_security_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ole32_for_co_initialize_security(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_co_create_instance_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ole32_for_co_create_instance(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_co_set_proxy_blanket_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ole32_for_co_set_proxy_blanket(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_create_dxgi_factory1_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dxgi_for_create_dxgi_factory1(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_co_uninitialize_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ole32_for_co_uninitialize(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_schema_one_fragment(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_iso_8601_utc_timestamp_format(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_wmi_root_cimv2_namespace(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_os_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_get_module_handle_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_get_module_handle_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ntdll_module_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_rtl_get_version_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_windows_family_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_windows_11_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_windows_10_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_os_name_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_os_build_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_os_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_os_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_registry_key_path(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_frequency_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_processor_name_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_base_mhz_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_name_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_logical_processors_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_sse2_or_lower_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_avx512_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_avx_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_sse42_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_sse41_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_arch_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_sse41_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_sse42_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_avx_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_avx2_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_avx512f_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_cpu_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_total_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_available_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_load_pct_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_sticks_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_physical_memory_inventory_query(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_wql_dialect(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_json_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_stick_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_capacity_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_speed_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_manufacturer_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_device_locator_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_memory_type_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_capacity_megabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_speed_megahertz_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_memory_slot_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_slot_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_memory_manufacturer_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_manufacturer_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ddr_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ddr2_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ddr3_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ddr4_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ddr5_memory_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_type_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_stick_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_json_section_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_motherboard_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_baseboard_product_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_baseboard_product_query(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_baseboard_product_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_baseboard_serial_number_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_baseboard_serial_number_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_bios_version_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_bios_version_query(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_bios_version_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_bios_release_date_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_bios_release_date_query(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_bios_release_date_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_motherboard_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpus_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_name_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_vendor_id_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_device_id_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_vram_megabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_shared_megabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_drivers_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_adapter_class_registry_path(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_driver_description_registry_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_driver_version_registry_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_driver_date_registry_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_description_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_version_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_date_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_driver_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_gpu_drivers_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hags_enabled_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_true_for_hags(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_json_false_for_hags(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_d3d11_feature_level_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_9_1_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_9_2_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_9_3_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_10_0_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_10_1_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_11_0_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_11_1_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_12_0_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_12_1_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_12_2_or_later_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_feature_level_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_displays_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_enum_display_devices_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_user32_for_enum_display_devices_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_enum_display_settings_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_user32_for_enum_display_settings_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_device_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_width_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_height_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_refresh_hz_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_bits_per_pixel_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_display_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_displays_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_monitor_serials_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_get_class_devs_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_get_class_devs_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_empty_monitor_serials_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_enum_device_info_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_enum_device_info(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_open_dev_reg_key_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_open_dev_reg_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_edid_registry_value_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_default_monitor_serial(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_monitor_serial_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_monitor_serial_json_quote_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_monitor_serial_json_quote_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_destroy_device_info_list_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_destroy_device_info_list(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_monitor_serials_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dwm_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dwm_composition_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_refresh_hz_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dwm_json_property_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_refresh_hz_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_dwm_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_storage_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_storage_drives_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_drive_inventory_query(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_wql_dialect(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_disk_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_model_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_serial_number_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_interface_type_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_media_type_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_disk_size_property_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_unknown_disk_model_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_empty_disk_serial_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_disk_interface_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_disk_media_type_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_disk_size_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nvme_storage_classification(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nvme_lowercase_storage_classification(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_scsi_disk_interface_marker(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nvme_ssd_storage_type(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_fixed_disk_media_marker(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ssd_disk_media_marker(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_sata_ssd_storage_type(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_removable_disk_media_marker_lowercase(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_removable_disk_media_marker(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_removable_storage_type(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_model_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_serial_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_interface_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_type_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_size_gigabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_disk_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_storage_volumes_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_letter_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_total_gigabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_free_gigabytes_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_volume_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_storage_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_usb_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_usb_controller_device_wmi_query(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_usb_controller_device_wmi_dialect(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_usb_device_count_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_usb_hubs_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_usb_hub_wmi_query(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_usb_hub_wmi_dialect(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_usb_hub_name_property(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_usb_hub_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_usb_hubs_array_and_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mice_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_d_get_hid_guid_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_get_hid_guid(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_enum_device_interfaces_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_enum_device_interfaces(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setup_di_get_device_interface_detail_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_setupapi_for_get_device_interface_detail_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_create_file_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_create_file_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_d_get_attributes_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_get_attributes(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_d_get_preparsed_data_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_get_preparsed_data(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_p_get_caps_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_get_caps(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_d_get_product_string_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_get_product_string(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unknown_hid_product_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_name_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_vendor_id_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_product_id_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_report_size_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mouse_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_d_free_preparsed_data_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_for_free_preparsed_data(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hid_mice_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_power_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_custom_power_plan_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_high_performance_power_plan_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_balanced_power_plan_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_power_saver_plan_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ultimate_performance_power_plan_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_power_plan_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_power_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_ntdll_for_query_timer_resolution(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_nt_query_timer_resolution_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_current_resolution_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_minimum_resolution_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_maximum_resolution_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_maximum_milliseconds_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_processes_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_process_count_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_thread_count_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_processes_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_json_array_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_security_center2_wmi_namespace(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_antivirus_wmi_query_dialect(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_antivirus_display_name_property(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_antivirus_product_state_property(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_unknown_antivirus_product_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_json_item_comma(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_name_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_enabled_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_bar_registry_subkey(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_allow_auto_game_mode_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_mode_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_auto_game_mode_enabled_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_config_store_registry_subkey(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_dvr_enabled_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_dvr_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_dvr_fse_behavior_mode_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_fse_behavior_mode_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_game_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_uptime_seconds_json_field_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_unsigned_long_long_decimal_format(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_total_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_available_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_total_virtual_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_avail_virtual_mb_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_pagefile_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_network_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_tcpip_parameters_registry_subkey(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hostname_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_hostname_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_network_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_firmware_json_object_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_firmware_environment_zero_vendor_guid(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_legacy_bios_boot_mode(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_uefi_boot_mode(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_boot_mode_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_secure_boot_state_registry_subkey(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_uefi_secure_boot_enabled_registry_value(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_tpm_service_registry_subkey(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_tpm_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_firmware_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_host_environment_json_object_close(
    const std::uint8_t* protected_source);

[[nodiscard]] char* allocate_reg_enum_key_ex_a_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_advapi32_for_reg_enum_key_ex_a(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_create_device_export_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_d3d11_for_create_device(
    const std::uint8_t* protected_source);

[[nodiscard]] const char* virtualbox_hypervisor_signature() noexcept;
[[nodiscard]] const char* parallels_hypervisor_signature() noexcept;
[[nodiscard]] const char* bhyve_hypervisor_signature() noexcept;
[[nodiscard]] const char* qemu_hypervisor_signature() noexcept;
[[nodiscard]] const char* x86_64_sse2_architecture_label() noexcept;
[[nodiscard]] const char* hard_disk_classification_label() noexcept;
using GetSystemInfoFunction = decltype(&::GetSystemInfo);
using GetSystemTimeFunction = decltype(&::GetSystemTime);
using GetModuleHandleAFunction = decltype(&::GetModuleHandleA);
using GlobalMemoryStatusExFunction = decltype(&::GlobalMemoryStatusEx);
using RegOpenKeyExAFunction = decltype(&::RegOpenKeyExA);
using RegQueryValueExAFunction = decltype(&::RegQueryValueExA);
using RegCloseKeyFunction = decltype(&::RegCloseKey);
using RegEnumKeyExAFunction = decltype(&::RegEnumKeyExA);
using RtlGetVersionFunction = NTSTATUS (NTAPI*)(PRTL_OSVERSIONINFOW);
using CoInitializeExFunction = decltype(&::CoInitializeEx);
using CoInitializeSecurityFunction = decltype(&::CoInitializeSecurity);
using CoCreateInstanceFunction = decltype(&::CoCreateInstance);
using CoSetProxyBlanketFunction = decltype(&::CoSetProxyBlanket);
using CreateDxgiFactory1Function = decltype(&::CreateDXGIFactory1);
using D3D11CreateDeviceFunction = decltype(&::D3D11CreateDevice);
using EnumDisplayDevicesAFunction = decltype(&::EnumDisplayDevicesA);
using EnumDisplaySettingsAFunction = decltype(&::EnumDisplaySettingsA);
using SetupDiGetClassDevsAFunction = decltype(&::SetupDiGetClassDevsA);
using SetupDiEnumDeviceInfoFunction = decltype(&::SetupDiEnumDeviceInfo);
using SetupDiOpenDevRegKeyFunction = decltype(&::SetupDiOpenDevRegKey);
using SetupDiDestroyDeviceInfoListFunction = decltype(&::SetupDiDestroyDeviceInfoList);
using HidDGetHidGuidFunction = decltype(&::HidD_GetHidGuid);
using SetupDiEnumDeviceInterfacesFunction = decltype(&::SetupDiEnumDeviceInterfaces);
using SetupDiGetDeviceInterfaceDetailAFunction =
    decltype(&::SetupDiGetDeviceInterfaceDetailA);
using CreateFileAFunction = decltype(&::CreateFileA);
using HidDGetAttributesFunction = decltype(&::HidD_GetAttributes);
using HidDGetPreparsedDataFunction = decltype(&::HidD_GetPreparsedData);
using HidPGetCapsFunction = decltype(&::HidP_GetCaps);
using HidDGetProductStringFunction = decltype(&::HidD_GetProductString);
using HidDFreePreparsedDataFunction = decltype(&::HidD_FreePreparsedData);
using CoUninitializeFunction = decltype(&::CoUninitialize);



extern GetSystemInfoFunction get_system_info_binding;
[[nodiscard]] GetSystemTimeFunction resolve_get_system_time_import() noexcept;
[[nodiscard]] GetModuleHandleAFunction resolve_get_module_handle_a_import() noexcept;
[[nodiscard]] GlobalMemoryStatusExFunction resolve_global_memory_status_ex_import() noexcept;
[[nodiscard]] RegOpenKeyExAFunction resolve_reg_open_key_ex_a_import() noexcept;
[[nodiscard]] RegQueryValueExAFunction resolve_reg_query_value_ex_a_import() noexcept;
[[nodiscard]] RegCloseKeyFunction resolve_reg_close_key_import() noexcept;
[[nodiscard]] RegEnumKeyExAFunction resolve_reg_enum_key_ex_a_import() noexcept;
[[nodiscard]] CoInitializeExFunction resolve_co_initialize_ex_import() noexcept;
[[nodiscard]] CoInitializeSecurityFunction resolve_co_initialize_security_import() noexcept;
[[nodiscard]] CoCreateInstanceFunction resolve_co_create_instance_import() noexcept;
[[nodiscard]] CoSetProxyBlanketFunction resolve_co_set_proxy_blanket_import() noexcept;
[[nodiscard]] CreateDxgiFactory1Function resolve_create_dxgi_factory1_import() noexcept;
[[nodiscard]] D3D11CreateDeviceFunction resolve_d3d11_create_device_import() noexcept;
[[nodiscard]] EnumDisplayDevicesAFunction resolve_enum_display_devices_a_import() noexcept;
[[nodiscard]] EnumDisplaySettingsAFunction resolve_enum_display_settings_a_import() noexcept;
[[nodiscard]] SetupDiGetClassDevsAFunction resolve_setup_di_get_class_devs_a_import() noexcept;
[[nodiscard]] SetupDiEnumDeviceInfoFunction resolve_setup_di_enum_device_info_import() noexcept;
[[nodiscard]] SetupDiOpenDevRegKeyFunction resolve_setup_di_open_dev_reg_key_import() noexcept;
[[nodiscard]] SetupDiDestroyDeviceInfoListFunction
resolve_setup_di_destroy_device_info_list_import() noexcept;
[[nodiscard]] HidDGetHidGuidFunction resolve_hid_d_get_hid_guid_import() noexcept;
[[nodiscard]] SetupDiEnumDeviceInterfacesFunction
resolve_setup_di_enum_device_interfaces_import() noexcept;
[[nodiscard]] SetupDiGetDeviceInterfaceDetailAFunction
resolve_setup_di_get_device_interface_detail_a_import() noexcept;
[[nodiscard]] CreateFileAFunction resolve_create_file_a_import() noexcept;
[[nodiscard]] HidDGetAttributesFunction resolve_hid_d_get_attributes_import() noexcept;
[[nodiscard]] HidDGetPreparsedDataFunction
resolve_hid_d_get_preparsed_data_import() noexcept;
[[nodiscard]] HidPGetCapsFunction resolve_hid_p_get_caps_import() noexcept;
[[nodiscard]] HidDGetProductStringFunction
resolve_hid_d_get_product_string_import() noexcept;
[[nodiscard]] HidDFreePreparsedDataFunction
resolve_hid_d_free_preparsed_data_import() noexcept;
[[nodiscard]] CoUninitializeFunction resolve_co_uninitialize_import() noexcept;
void register_create_directory_w_binding() noexcept;
void register_find_first_file_w_binding() noexcept;
void register_find_next_file_w_binding() noexcept;
void register_find_close_binding() noexcept;


[[nodiscard]] char* allocate_kernel32_for_get_process_id(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_blocked_mapping_event_name(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_text_section_crc_mismatch_detail_format(
    const std::uint8_t* protected_source);
[[nodiscard]] wchar_t* allocate_edge_update_credentials_path_format(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_collected_at_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_x86_64_avx2_label(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_memory_sticks_json_array_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_current_milliseconds_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_timer_minimum_milliseconds_json_prefix(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_json_object_open(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_antivirus_json_object_close(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_auto_game_mode_json_key(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_secure_boot_json_key(
    const std::uint8_t* protected_source);

}
