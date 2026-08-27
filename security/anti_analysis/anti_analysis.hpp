#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace makima::security::anti_analysis {


void append_probe_scalar(std::vector<std::byte>& bytes, std::byte value);
void append_low_order_probe_scalar(
    std::vector<std::byte>& bytes,
    std::uint32_t value);
void append_probe_integer_little_endian(
    std::vector<std::byte>& bytes,
    std::uint32_t value);
void append_probe_address_little_endian(
    std::vector<std::byte>& bytes,
    std::uint64_t value);
void emit_native_debug_probe(
    std::uintptr_t reserved_context,
    std::vector<std::byte>& bytes,
    std::uintptr_t probe_target);


[[nodiscard]] bool early_nt_global_flag_debug_bits_are_clear() noexcept;
[[nodiscard]] bool peb_being_debugged_is_clear() noexcept;


void allocate_readwrite_region_descriptor(
    std::uintptr_t caller_context,
    std::uintptr_t* descriptor,
    std::size_t requested_size) noexcept;


void finalize_executable_region_descriptor(
    std::uintptr_t caller_context,
    const std::uintptr_t* descriptor) noexcept;


[[nodiscard]] std::uint64_t current_process_has_no_remote_debugger() noexcept;


[[nodiscard]] std::uint64_t current_process_debug_flags_allow_execution() noexcept;


[[nodiscard]] std::uint64_t current_process_has_no_debug_object() noexcept;


[[nodiscard]] std::uint64_t parent_process_image_is_allowed() noexcept;


void bind_flush_instruction_cache() noexcept;
void bind_get_tick_count() noexcept;
void bind_get_thread_context() noexcept;
void bind_check_remote_debugger_present() noexcept;
void bind_query_full_process_image_name() noexcept;


[[nodiscard]] const wchar_t* x32dbg_process_token() noexcept;
[[nodiscard]] const wchar_t* ollydbg_process_token() noexcept;
[[nodiscard]] const wchar_t* windbg_process_token() noexcept;
[[nodiscard]] const wchar_t* dbgsrv_process_token() noexcept;
[[nodiscard]] const wchar_t* immunity_debugger_process_token() noexcept;
[[nodiscard]] const wchar_t* ida_process_token() noexcept;
[[nodiscard]] const wchar_t* ida64_process_token() noexcept;
[[nodiscard]] const wchar_t* ghidra_process_token() noexcept;
[[nodiscard]] const wchar_t* binary_ninja_process_token() noexcept;
[[nodiscard]] const wchar_t* radare2_process_token() noexcept;
[[nodiscard]] const wchar_t* iaito_process_token() noexcept;
[[nodiscard]] const wchar_t* dnspy_process_token() noexcept;
[[nodiscard]] const wchar_t* dotpeek_process_token() noexcept;
[[nodiscard]] const wchar_t* ilspy_process_token() noexcept;
[[nodiscard]] const wchar_t* de4dot_process_token() noexcept;
[[nodiscard]] const wchar_t* pe_bear_process_token() noexcept;
[[nodiscard]] const wchar_t* cff_explorer_process_token() noexcept;
[[nodiscard]] const wchar_t* pe_studio_process_token() noexcept;
[[nodiscard]] const wchar_t* editor_010_process_token() noexcept;
[[nodiscard]] const wchar_t* process_hacker_process_token() noexcept;




[[nodiscard]] std::uint64_t analysis_process_blacklist_check() noexcept;


[[nodiscard]] std::uint64_t loaded_module_names_are_clean_from_peb() noexcept;


[[nodiscard]] std::uint64_t ntdll_probe_exports_are_unhooked() noexcept;


[[nodiscard]] bool process_heap_debug_flags_are_clear() noexcept;




[[nodiscard]] const char* native_debugger_environment_check(
    std::uintptr_t logger_handle,
    std::uintptr_t log_level) noexcept;


char* allocate_get_thread_context_import_name(
    const std::uint16_t* protected_source);
char* allocate_kernel32_dll_for_get_thread_context(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);




char* allocate_flush_instruction_cache(std::int64_t protected_source);
char* allocate_kernel32_dll(const std::byte* protected_source);
char* allocate_get_tick_count(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
char* allocate_kernel32_dll_for_get_tick_count(
    std::int64_t protected_source);
char* allocate_check_remote_debugger_present(std::int64_t protected_source);
char* allocate_kernel32_dll_for_check_remote_debugger_present(
    std::int64_t protected_source);
char* allocate_query_full_process_image_name_w(std::int64_t protected_source);
char* allocate_kernel32_dll_for_query_full_process_image_name_w(
    std::int64_t protected_source);


wchar_t* allocate_conhost_executable_name(
    const std::uint16_t* protected_source);



wchar_t* allocate_explorer_exe(const std::uint16_t* protected_source);
wchar_t* allocate_svchost_exe(const std::uint16_t* protected_source);
wchar_t* allocate_sihost_exe(const std::uint16_t* protected_source);

wchar_t* allocate_userinit_executable_name(
    const std::uint16_t* protected_source);
wchar_t* allocate_runtime_broker_exe(std::int64_t protected_source);


wchar_t* allocate_secondary_search_host_executable_name(
    const std::uint16_t* protected_source);
wchar_t* allocate_shell_experience_host_exe(std::int64_t protected_source);
wchar_t* allocate_application_frame_host_exe(std::int64_t protected_source);
wchar_t* allocate_cmd_exe(const std::uint16_t* protected_source);
wchar_t* allocate_powershell_exe(const std::uint16_t* protected_source);
wchar_t* allocate_pwsh_exe(const std::uint16_t* protected_source);
wchar_t* allocate_windows_terminal_exe(std::int64_t protected_source);
wchar_t* allocate_wt_exe(const std::uint16_t* protected_source);
wchar_t* allocate_chrome_exe(const std::uint16_t* protected_source);
wchar_t* allocate_msedge_exe(const std::uint16_t* protected_source);
wchar_t* allocate_firefox_exe(std::int64_t protected_source);
wchar_t* allocate_opera_exe(const std::uint16_t* protected_source);
wchar_t* allocate_brave_exe(const std::uint16_t* protected_source);
wchar_t* allocate_vivaldi_exe(std::int64_t protected_source);
wchar_t* allocate_iexplore_exe(const std::uint16_t* protected_source);
wchar_t* allocate_7z_fm_exe(const std::uint16_t* protected_source);
wchar_t* allocate_winrar_exe(const std::uint16_t* protected_source);
wchar_t* allocate_total_commander_exe(const std::uint16_t* protected_source);
wchar_t* allocate_discord_exe(const std::uint16_t* protected_source);
wchar_t* allocate_discord_ptb_exe(std::int64_t protected_source);
wchar_t* allocate_discord_canary_exe(const std::uint16_t* protected_source);
wchar_t* allocate_telegram_exe(std::int64_t protected_source);
wchar_t* allocate_rundll32_exe(std::int64_t protected_source);
wchar_t* allocate_taskmgr_exe(std::int64_t protected_source);
wchar_t* allocate_dllhost_exe(const std::uint16_t* protected_source);
wchar_t* allocate_cheatengine_process_token(
    const std::uint16_t* protected_source);
wchar_t* allocate_cheat_engine_process_token(
    const std::uint16_t* protected_source);
wchar_t* allocate_ceserver_process_token(
    const std::uint16_t* protected_source);
wchar_t* allocate_artmoney_process_token(
    const std::uint16_t* protected_source);
wchar_t* allocate_squalr_process_token(
    const std::uint16_t* protected_source);
wchar_t* allocate_x64dbg_process_token(
    const std::uint16_t* protected_source);




[[nodiscard]] const wchar_t* powershell_image_name() noexcept;
[[nodiscard]] const wchar_t* pwsh_image_name() noexcept;
[[nodiscard]] const wchar_t* windows_terminal_image_name() noexcept;
[[nodiscard]] const wchar_t* terminal_host_image_name();
[[nodiscard]] const wchar_t* wt_image_name() noexcept;
[[nodiscard]] const wchar_t* chrome_image_name() noexcept;
[[nodiscard]] const wchar_t* edge_image_name() noexcept;
[[nodiscard]] const wchar_t* firefox_image_name() noexcept;
[[nodiscard]] const wchar_t* opera_image_name() noexcept;
[[nodiscard]] const wchar_t* brave_image_name() noexcept;
[[nodiscard]] const wchar_t* vivaldi_image_name() noexcept;
[[nodiscard]] const wchar_t* internet_explorer_image_name() noexcept;
[[nodiscard]] const wchar_t* seven_zip_file_manager_image_name() noexcept;
[[nodiscard]] const wchar_t* winrar_image_name() noexcept;
[[nodiscard]] const wchar_t* total_commander_image_name() noexcept;
[[nodiscard]] const wchar_t* discord_image_name() noexcept;
[[nodiscard]] const wchar_t* discord_ptb_image_name() noexcept;
[[nodiscard]] const wchar_t* discord_canary_image_name() noexcept;
[[nodiscard]] const wchar_t* telegram_image_name() noexcept;
[[nodiscard]] const wchar_t* rundll32_image_name() noexcept;
[[nodiscard]] const wchar_t* task_manager_image_name() noexcept;
[[nodiscard]] const wchar_t* dll_host_image_name() noexcept;




wchar_t* allocate_x32dbg(const std::uint16_t* protected_source);
wchar_t* allocate_ollydbg(const std::uint16_t* protected_source);
wchar_t* allocate_windbg(const std::uint16_t* protected_source);
wchar_t* allocate_dbgsrv(const std::uint16_t* protected_source);
wchar_t* allocate_immunitydebugger(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
wchar_t* allocate_ida64_exe(const std::uint16_t* protected_source);
wchar_t* allocate_ghidra(const std::uint16_t* protected_source);
wchar_t* allocate_radare2(const std::uint16_t* protected_source);
wchar_t* allocate_iaito(const std::uint16_t* protected_source);
wchar_t* allocate_dnspy(const std::uint16_t* protected_source);
wchar_t* allocate_dotpeek(const std::uint16_t* protected_source);
wchar_t* allocate_ilspy(const std::uint16_t* protected_source);
wchar_t* allocate_de4dot(const std::uint16_t* protected_source);
wchar_t* allocate_pe_bear(const std::uint16_t* protected_source);
wchar_t* allocate_cffexplorer(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
wchar_t* allocate_pestudio(const std::uint16_t* protected_source);
wchar_t* allocate_010editor(const std::uint16_t* protected_source);
wchar_t* allocate_processhacker(const std::uint16_t* protected_source);




[[nodiscard]] const wchar_t* system_informer_process_token() noexcept;
[[nodiscard]] const wchar_t* b_sentinel_process_token() noexcept;
[[nodiscard]] const wchar_t* process_explorer_process_token() noexcept;
[[nodiscard]] const wchar_t* reclass_process_token() noexcept;
[[nodiscard]] const wchar_t* scylla_process_token() noexcept;
[[nodiscard]] const wchar_t* fiddler_process_token() noexcept;
[[nodiscard]] const wchar_t* http_toolkit_process_token() noexcept;
[[nodiscard]] const wchar_t* proxyman_process_token() noexcept;
[[nodiscard]] const wchar_t* reqable_process_token() noexcept;
[[nodiscard]] const wchar_t* http_analyzer_process_token() noexcept;
[[nodiscard]] const wchar_t* http_debugger_pro_process_token() noexcept;
[[nodiscard]] const wchar_t* http_debugger_process_token() noexcept;
[[nodiscard]] const wchar_t* bracket_sentinel_process_token() noexcept;
[[nodiscard]] const wchar_t* charles_process_token() noexcept;
[[nodiscard]] const wchar_t* burp_suite_process_token() noexcept;
[[nodiscard]] const wchar_t* echo_mirage_process_token() noexcept;
[[nodiscard]] const wchar_t* wireshark_process_token() noexcept;
[[nodiscard]] const wchar_t* tshark_process_token() noexcept;
[[nodiscard]] const wchar_t* dumpcap_process_token() noexcept;
[[nodiscard]] const wchar_t* rawcap_process_token() noexcept;
[[nodiscard]] const wchar_t* smsniff_process_token() noexcept;
[[nodiscard]] const wchar_t* network_miner_process_token() noexcept;
[[nodiscard]] const wchar_t* windump_process_token() noexcept;
[[nodiscard]] const wchar_t* equals_sentinel_process_token() noexcept;
[[nodiscard]] const wchar_t* api_monitor_process_token() noexcept;
[[nodiscard]] const wchar_t* rohitab_process_token() noexcept;
[[nodiscard]] const wchar_t* winapi_override_process_token() noexcept;
[[nodiscard]] const wchar_t* spy_studio_process_token() noexcept;
[[nodiscard]] const wchar_t* wpe_pro_process_token() noexcept;
[[nodiscard]] const wchar_t* xenos_process_token() noexcept;
[[nodiscard]] const wchar_t* extreme_injector_process_token() noexcept;
[[nodiscard]] const wchar_t* gh_injector_process_token() noexcept;



[[nodiscard]] const wchar_t* http_debugger_module_token() noexcept;
[[nodiscard]] const wchar_t* winapi_override_module_token() noexcept;
[[nodiscard]] const wchar_t* spy_studio_module_token() noexcept;
[[nodiscard]] const wchar_t* echo_mirage_module_token() noexcept;
[[nodiscard]] const wchar_t* fiddler_core_module_token() noexcept;
[[nodiscard]] const wchar_t* titanium_module_token() noexcept;
[[nodiscard]] const wchar_t* http_toolkit_module_token() noexcept;



[[nodiscard]] const char* hardware_breakpoint_detail() noexcept;
[[nodiscard]] const char* hardware_breakpoint_format() noexcept;
[[nodiscard]] const char* hardware_breakpoint_event() noexcept;
[[nodiscard]] const char* nt_global_flag_detail() noexcept;
[[nodiscard]] const char* nt_global_flag_format() noexcept;
[[nodiscard]] const char* nt_global_flag_event() noexcept;
[[nodiscard]] const char* tooling_process_detail() noexcept;
[[nodiscard]] const char* tooling_process_format() noexcept;
[[nodiscard]] const char* tooling_process_event() noexcept;
[[nodiscard]] const wchar_t* ssl_key_log_environment_name() noexcept;
[[nodiscard]] const wchar_t* ssl_key_log_environment_name_for_clear() noexcept;
[[nodiscard]] const char* ssl_key_log_detail() noexcept;
[[nodiscard]] const char* ssl_key_log_format() noexcept;
[[nodiscard]] const char* ssl_key_log_event() noexcept;
[[nodiscard]] const char* suspicious_module_detail() noexcept;
[[nodiscard]] const char* suspicious_module_format() noexcept;
[[nodiscard]] const char* suspicious_module_event() noexcept;
[[nodiscard]] const char* invalid_handle_detail() noexcept;
[[nodiscard]] const char* invalid_handle_format() noexcept;
[[nodiscard]] const char* invalid_handle_event() noexcept;
[[nodiscard]] const char* heap_flags_detail() noexcept;
[[nodiscard]] const char* heap_flags_format() noexcept;
[[nodiscard]] const char* heap_flags_event() noexcept;
[[nodiscard]] const char* remote_debugger_verbose_detail() noexcept;
[[nodiscard]] const char* remote_debugger_event() noexcept;
[[nodiscard]] const char* invalid_handle_verbose_detail() noexcept;
[[nodiscard]] const char* invalid_handle_verbose_event() noexcept;
[[nodiscard]] const char* heap_flags_verbose_detail() noexcept;
[[nodiscard]] const char* heap_flags_verbose_event() noexcept;
[[nodiscard]] const char* timing_anomaly_detail() noexcept;
[[nodiscard]] const char* timing_anomaly_event() noexcept;
[[nodiscard]] const char* bad_parent_process_detail() noexcept;
[[nodiscard]] const char* bad_parent_process_event() noexcept;

}
