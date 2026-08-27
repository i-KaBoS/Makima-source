#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace makima::process::pe_mapping::literals {

struct MappedImageStateBlock final {
    std::array<std::byte, 32> bytes{};
};

[[nodiscard]] std::string launch_progress_event_format();

[[nodiscard]] char* allocate_remote_write_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_get_thread_context_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_stub_alloc_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_set_thread_context_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_nt_create_thread_ex_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_process_exited_after_resume_message(
    std::int64_t protected_source);

[[nodiscard]] std::string virtual_query_api_name();

[[nodiscard]] std::string stack_frame_resides_in_page_execute_readwrite_memory_message();

[[nodiscard]] std::string anti_tamper_rwx_frame_event_name();

[[nodiscard]] std::string stack_frame_resides_in_page_execute_writecopy_memory_message();

[[nodiscard]] std::string anti_tamper_executable_writecopy_frame_event_name();

[[nodiscard]] std::string import_dll_not_found_message();

[[nodiscard]] std::string label_detail_format();

[[nodiscard]] std::string failed_to_resolve_import_message();

[[nodiscard]] char* allocate_alloc_failed_for_stub_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_secondary_nt_create_thread_ex_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_injection_timed_out_15s_message(
    std::int64_t protected_source);

[[nodiscard]] std::string create_toolhelp32_snapshot_api_name();

[[nodiscard]] std::string toolhelp_snapshot_kernel32_module_name();

[[nodiscard]] std::string process_enumeration_kernel32_module_name();

[[nodiscard]] std::string process32_next_w_api_name();

[[nodiscard]] std::string process_next_kernel32_module_name();

[[nodiscard]] std::string local_free_api_name();

[[nodiscard]] std::string local_free_kernel32_module_name();

[[nodiscard]] std::string is_wow64_process_api_name();

[[nodiscard]] std::string wow64_query_kernel32_module_name();




[[nodiscard]] char16_t* decode_protected_utf16_140543cf0(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_140546d80(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_140549c80(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_14054c640(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_14054f760(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_140554d00(
    const char16_t* source);

[[nodiscard]] char16_t* decode_protected_utf16_140556180(
    const char16_t* source);

[[nodiscard]] std::string message_with_code_format();

[[nodiscard]] std::string error_code_mk_1002_for_buffer_validation();

[[nodiscard]] std::string invalid_payload_message_for_dos_header_validation();

[[nodiscard]] std::string error_code_mk_1002_for_dos_header_validation();

[[nodiscard]] std::string invalid_payload_message_for_nt_header_bounds_validation();

[[nodiscard]] std::string error_code_mk_1002_for_nt_header_bounds_validation();

[[nodiscard]] std::string invalid_payload_message_for_pe_signature_validation();

[[nodiscard]] std::string error_code_mk_1002_for_pe_signature_validation();

[[nodiscard]] std::string invalid_payload_format_message_for_dll_characteristics_validation();

[[nodiscard]] std::string error_code_mk_1002_for_dll_characteristics_validation();

[[nodiscard]] std::string initialization_failed_message_for_mk_2001();

[[nodiscard]] std::string error_code_mk_2001();

[[nodiscard]] std::wstring se_debug_privilege_api_name();

[[nodiscard]] std::wstring se_impersonate_privilege_api_name();

[[nodiscard]] std::string initialization_failed_message_for_mk_2002();

[[nodiscard]] std::string error_code_mk_2002();

[[nodiscard]] std::string kernel_hyperspace_ready_message();

[[nodiscard]] std::string initializing_message();

[[nodiscard]] std::wstring ntoskrnl_exe_module_name();

[[nodiscard]] std::string ex_allocate_pool_with_tag_api_name();

[[nodiscard]] std::string ex_free_pool_with_tag_api_name();

[[nodiscard]] std::string io_allocate_mdl_api_name();

[[nodiscard]] std::string io_free_mdl_api_name();

[[nodiscard]] std::string mm_probe_and_lock_process_pages_api_name();

[[nodiscard]] std::string zw_allocate_virtual_memory_api_name();

[[nodiscard]] std::string zw_close_api_name();

[[nodiscard]] std::string zw_protect_virtual_memory_api_name();

[[nodiscard]] std::string ob_open_object_by_pointer_api_name();

[[nodiscard]] std::string kernel_symbol_ps_process_type();

[[nodiscard]] std::string error_code_mk_3003();

[[nodiscard]] std::string error_code_mk_3001();

[[nodiscard]] std::string kernel_type_eprocess_for_active_process_links();

[[nodiscard]] std::string kernel_symbol_active_process_links();

[[nodiscard]] std::string kernel_symbol_image_file_name();

[[nodiscard]] std::string kernel_type_eprocess_for_directory_table_base();

[[nodiscard]] std::string kernel_symbol_directory_table_base();

[[nodiscard]] std::string kernel_symbol_kprocess();

[[nodiscard]] std::string kernel_symbol_peb();

[[nodiscard]] std::string kernel_type_eprocess_for_vad_root();

[[nodiscard]] std::string kernel_symbol_vad_root();

[[nodiscard]] std::string kernel_type_eprocess_for_apc_state();

[[nodiscard]] std::string kernel_symbol_apc_state();

[[nodiscard]] std::string kernel_type_kthread_for_process();

[[nodiscard]] std::string kernel_symbol_process();

[[nodiscard]] std::string kernel_symbol_kapc_state();

[[nodiscard]] std::string kernel_symbol_previous_mode();

[[nodiscard]] std::string kernel_type_kthread_for_trap_frame();

[[nodiscard]] std::string kernel_symbol_trap_frame();

[[nodiscard]] std::string kernel_type_kthread_for_state();

[[nodiscard]] std::string kernel_type_kthread_for_thread_list_head();

[[nodiscard]] std::string kernel_symbol_thread_list_head();

[[nodiscard]] std::string kernel_type_eprocess_for_thread_list_entry();

[[nodiscard]] char* allocate_kernel_symbol_thread_list_entry(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_kernel_symbol_ethread(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_kernel_symbol_rip(
    std::int64_t protected_source);

[[nodiscard]] std::string kernel_type_ktrap_frame_for_rip();

[[nodiscard]] char* allocate_kernel_symbol_rsp(
    std::int64_t protected_source);

[[nodiscard]] std::string kernel_type_ktrap_frame_for_rsp();

[[nodiscard]] char* allocate_error_code_mk_3002(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_please_launch_the_game_now_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_waiting_for_game_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_timed_out_waiting_for_game_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_4003(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_injecting_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_sleep_api_name(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_sleep_kernel32_module_name(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_target_process_not_found_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_4001(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_target_process_kernel_info_not_found_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_4002(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_5001a(
    std::int64_t protected_source);

[[nodiscard]] std::string ntstatus_hex_format_for_mk_5001a();

[[nodiscard]] char* allocate_error_code_mk_5001b(
    std::int64_t protected_source);

[[nodiscard]] std::string ntstatus_hex_format_for_mk_5001b();

[[nodiscard]] char* allocate_error_code_mk_5001c(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_page_preparation_failed_message(
    std::int64_t protected_source);

[[nodiscard]] std::string error_code_mk_5002_for_page_preparation();

[[nodiscard]] std::string error_code_mk_5002_for_page_preparation_detail();

[[nodiscard]] char* allocate_error_code_mk_6002(
    std::int64_t protected_source);

[[nodiscard]] std::string error_code_mk_6003_for_secondary_component_resolution();

[[nodiscard]] char* allocate_component_resolution_failed_message(
    std::int64_t protected_source);

[[nodiscard]] std::string error_code_mk_6003_for_component_resolution();

[[nodiscard]] char* allocate_memory_write_failed_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_5003(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_no_suitable_execution_context_found_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_7001(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_execution_timeout_message(
    std::int64_t protected_source);

[[nodiscard]] char* allocate_error_code_mk_7002(
    std::int64_t protected_source);

}
