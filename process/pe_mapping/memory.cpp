







#include "memory.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>
#include <new>

namespace makima::process::pe_mapping::literals {
namespace {

template <std::size_t Extent>
[[nodiscard]] char16_t* allocate_rotated_xor_wide(
    const char16_t* source,
    const std::array<std::uint16_t, Extent>& xor_masks,
    const std::array<std::uint8_t, Extent>& left_rotations) {
    auto* decoded = static_cast<char16_t*>(
        ::operator new((Extent + 1U) * sizeof(char16_t)));
    for (std::size_t index = 0; index < Extent; ++index) {
        if (left_rotations[index] == 0xffU) {
            decoded[index] = static_cast<char16_t>(xor_masks[index]);
            continue;
        }
        const auto rotated = std::rotl(
            static_cast<std::uint16_t>(source[index]),
            static_cast<int>(left_rotations[index]));
        decoded[index] = static_cast<char16_t>(rotated ^ xor_masks[index]);
    }
    decoded[Extent] = u'\0';
    return decoded;
}

template <std::size_t Extent>
[[nodiscard]] char* allocate_narrow_literal(const char (&literal)[Extent]) {
    auto* output = static_cast<char*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}

}


[[nodiscard]] std::string launch_progress_event_format() {
    return "{\"event\":\"launch_progress\",\"data\":{\"percent\":%d,\"title\":\"%s\",\"sub\":\"%s\"}}";
}


[[nodiscard]] char* allocate_remote_write_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Remote write failed");
}


[[nodiscard]] char* allocate_get_thread_context_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("GetThreadContext failed");
}


[[nodiscard]] char* allocate_stub_alloc_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Stub alloc failed");
}


[[nodiscard]] char* allocate_set_thread_context_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("SetThreadContext failed");
}


[[nodiscard]] char* allocate_nt_create_thread_ex_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("NtCreateThreadEx failed");
}


[[nodiscard]] char* allocate_process_exited_after_resume_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Process exited after resume");
}


[[nodiscard]] std::string virtual_query_api_name() {
    return "VirtualQuery";
}


[[nodiscard]] std::string stack_frame_resides_in_page_execute_readwrite_memory_message() {
    return "stack frame resides in PAGE_EXECUTE_READWRITE memory";
}


[[nodiscard]] std::string anti_tamper_rwx_frame_event_name() {
    return "anti_tamper.rwx_frame";
}


[[nodiscard]] std::string stack_frame_resides_in_page_execute_writecopy_memory_message() {
    return "stack frame resides in PAGE_EXECUTE_WRITECOPY memory";
}


[[nodiscard]] std::string anti_tamper_executable_writecopy_frame_event_name() {
    return "anti_tamper.executable_writecopy_frame";
}


[[nodiscard]] std::string import_dll_not_found_message() {
    return "Import DLL not found";
}


[[nodiscard]] std::string label_detail_format() {
    return "%s: %s";
}


[[nodiscard]] std::string failed_to_resolve_import_message() {
    return "Failed to resolve import";
}


[[nodiscard]] char* allocate_alloc_failed_for_stub_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Alloc failed for stub");
}


[[nodiscard]] char* allocate_secondary_nt_create_thread_ex_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("NtCreateThreadEx failed");
}


[[nodiscard]] char* allocate_injection_timed_out_15s_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Injection timed out (15s)");
}


[[nodiscard]] std::string create_toolhelp32_snapshot_api_name() {
    return "CreateToolhelp32Snapshot";
}


[[nodiscard]] std::string toolhelp_snapshot_kernel32_module_name() {
    return "kernel32.dll";
}


[[nodiscard]] std::string process_enumeration_kernel32_module_name() {
    return "kernel32.dll";
}


[[nodiscard]] std::string process32_next_w_api_name() {
    return "Process32NextW";
}


[[nodiscard]] std::string process_next_kernel32_module_name() {
    return "kernel32.dll";
}


[[nodiscard]] std::string local_free_api_name() {
    return "LocalFree";
}


[[nodiscard]] std::string local_free_kernel32_module_name() {
    return "kernel32.dll";
}


[[nodiscard]] std::string is_wow64_process_api_name() {
    return "IsWow64Process";
}


[[nodiscard]] std::string wow64_query_kernel32_module_name() {
    return "kernel32.dll";
}



[[nodiscard]] char16_t* decode_protected_utf16_140543cf0(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 11> xor_masks{
        0x8c44, 0x80cc, 0x0427, 0xa068, 0x10af, 0xecd1,
        0xa079, 0xf038, 0xc0e6, 0xd081, 0x704b};
    constexpr std::array<std::uint8_t, 11> left_rotations{
        0x0a, 0x0d, 0x0a, 0x0c, 0x0c, 0x09,
        0x0c, 0x0c, 0x0c, 0x0c, 0x0b};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}



[[nodiscard]] char16_t* decode_protected_utf16_140546d80(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 12> xor_masks{
        0xc08e, 0x1013, 0x88c6, 0xe0a8, 0x9876, 0xdc26,
        0x60b8, 0xf0e8, 0xd02a, 0xb04f, 0x1299, 0x5027};
    constexpr std::array<std::uint8_t, 12> left_rotations{
        0x0e, 0x0b, 0x0b, 0x0b, 0x0a, 0x0a,
        0x0b, 0x09, 0x0b, 0x0c, 0x09, 0x0c};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}



[[nodiscard]] char16_t* decode_protected_utf16_140549c80(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 13> xor_masks{
        0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0,
        0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0};
    constexpr std::array<std::uint8_t, 13> left_rotations{};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}



[[nodiscard]] char16_t* decode_protected_utf16_14054c640(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 17> xor_masks{
        0x809b, 0x0090, 0x80c8, 0x0090, 0x0090, 0x0090,
        0x0090, 0x8034, 0x008e, 0x0090, 0x007d, 0x8086,
        0x8062, 0xc078, 0x203e, 0x00d8, 0xe08c};
    constexpr std::array<std::uint8_t, 17> left_rotations{
        0x0f, 0x00, 0x0f, 0x00, 0x00, 0x00,
        0x00, 0x0f, 0x0f, 0x00, 0x0f, 0x0f,
        0x0f, 0x0d, 0x0d, 0x0d, 0x0d};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}






[[nodiscard]] char16_t* decode_protected_utf16_14054f760(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 23> xor_masks{
        0x409d, 0x20cb, 0xc0e7, 0x8067, 0xa050, 0xc0ee,
        0x8075, 0x60dd, 0x0014, 0x609c, 0x40a2, 0x40fe,
        0x4068, 0x009c, 0x00fa, 0x00fa, 0x404f, 0x0087,
        0x00fa, 0x80bf, 0x6f3c, 0xcd95, 0x2b88};
    constexpr std::array<std::uint8_t, 23> left_rotations{
        0x0e, 0x0c, 0x0e, 0x0d, 0x0d, 0x0d,
        0x0d, 0x0d, 0x0d, 0x0d, 0x0d, 0x0e,
        0x0e, 0x0e, 0x00, 0x00, 0x0e, 0x0e,
        0x00, 0x0f, 0xff, 0xff, 0xff};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}



[[nodiscard]] char16_t* decode_protected_utf16_140554d00(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 7> xor_masks{
        0x0066, 0x0066, 0x0066, 0x0066, 0x0066, 0x0066, 0x0066};
    constexpr std::array<std::uint8_t, 7> left_rotations{};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}



[[nodiscard]] char16_t* decode_protected_utf16_140556180(
    const char16_t* source) {
    constexpr std::array<std::uint16_t, 14> xor_masks{
        0xf005, 0xf005, 0x013e, 0xf005, 0xf005, 0x00c0, 0xf802,
        0xf802, 0xf802, 0xf802, 0xf802, 0x00be, 0xf802, 0x0140};
    constexpr std::array<std::uint8_t, 14> left_rotations{
        0x0b, 0x0b, 0x00, 0x0b, 0x0b, 0x0f, 0x0a,
        0x0a, 0x0a, 0x0a, 0x0a, 0x0f, 0x0a, 0x0e};
    return allocate_rotated_xor_wide(
        source, xor_masks, left_rotations);
}


[[nodiscard]] std::string message_with_code_format() {
    return "%s (%s)";
}


[[nodiscard]] std::string error_code_mk_1002_for_buffer_validation() {
    return "MK-1002";
}


[[nodiscard]] std::string invalid_payload_message_for_dos_header_validation() {
    return "Invalid payload";
}


[[nodiscard]] std::string error_code_mk_1002_for_dos_header_validation() {
    return "MK-1002";
}


[[nodiscard]] std::string invalid_payload_message_for_nt_header_bounds_validation() {
    return "Invalid payload";
}


[[nodiscard]] std::string error_code_mk_1002_for_nt_header_bounds_validation() {
    return "MK-1002";
}


[[nodiscard]] std::string invalid_payload_message_for_pe_signature_validation() {
    return "Invalid payload";
}


[[nodiscard]] std::string error_code_mk_1002_for_pe_signature_validation() {
    return "MK-1002";
}


[[nodiscard]] std::string invalid_payload_format_message_for_dll_characteristics_validation() {
    return "Invalid payload format";
}


[[nodiscard]] std::string error_code_mk_1002_for_dll_characteristics_validation() {
    return "MK-1002";
}


[[nodiscard]] std::string initialization_failed_message_for_mk_2001() {
    return "Initialization failed";
}


[[nodiscard]] std::string error_code_mk_2001() {
    return "MK-2001";
}


[[nodiscard]] std::wstring se_debug_privilege_api_name() {
    return L"SeDebugPrivilege";
}


[[nodiscard]] std::wstring se_impersonate_privilege_api_name() {
    return L"SeImpersonatePrivilege";
}


[[nodiscard]] std::string initialization_failed_message_for_mk_2002() {
    return "Initialization failed";
}


[[nodiscard]] std::string error_code_mk_2002() {
    return "MK-2002";
}


[[nodiscard]] std::string kernel_hyperspace_ready_message() {
    return "Kernel hyperspace ready";
}


[[nodiscard]] std::string initializing_message() {
    return "Initializing...";
}


[[nodiscard]] std::wstring ntoskrnl_exe_module_name() {
    return L"ntoskrnl.exe";
}


[[nodiscard]] std::string ex_allocate_pool_with_tag_api_name() {
    return "ExAllocatePoolWithTag";
}


[[nodiscard]] std::string ex_free_pool_with_tag_api_name() {
    return "ExFreePoolWithTag";
}


[[nodiscard]] std::string io_allocate_mdl_api_name() {
    return "IoAllocateMdl";
}


[[nodiscard]] std::string io_free_mdl_api_name() {
    return "IoFreeMdl";
}


[[nodiscard]] std::string mm_probe_and_lock_process_pages_api_name() {
    return "MmProbeAndLockProcessPages";
}


[[nodiscard]] std::string zw_allocate_virtual_memory_api_name() {
    return "ZwAllocateVirtualMemory";
}


[[nodiscard]] std::string zw_close_api_name() {
    return "ZwClose";
}


[[nodiscard]] std::string zw_protect_virtual_memory_api_name() {
    return "ZwProtectVirtualMemory";
}


[[nodiscard]] std::string ob_open_object_by_pointer_api_name() {
    return "ObOpenObjectByPointer";
}


[[nodiscard]] std::string kernel_symbol_ps_process_type() {
    return "PsProcessType";
}


[[nodiscard]] std::string error_code_mk_3003() {
    return "MK-3003";
}


[[nodiscard]] std::string error_code_mk_3001() {
    return "MK-3001";
}


[[nodiscard]] std::string kernel_type_eprocess_for_active_process_links() {
    return "_EPROCESS";
}


[[nodiscard]] std::string kernel_symbol_active_process_links() {
    return "ActiveProcessLinks";
}


[[nodiscard]] std::string kernel_symbol_image_file_name() {
    return "ImageFileName";
}


[[nodiscard]] std::string kernel_type_eprocess_for_directory_table_base() {
    return "_EPROCESS";
}


[[nodiscard]] std::string kernel_symbol_directory_table_base() {
    return "DirectoryTableBase";
}


[[nodiscard]] std::string kernel_symbol_kprocess() {
    return "_KPROCESS";
}


[[nodiscard]] std::string kernel_symbol_peb() {
    return "Peb";
}


[[nodiscard]] std::string kernel_type_eprocess_for_vad_root() {
    return "_EPROCESS";
}


[[nodiscard]] std::string kernel_symbol_vad_root() {
    return "VadRoot";
}


[[nodiscard]] std::string kernel_type_eprocess_for_apc_state() {
    return "_EPROCESS";
}


[[nodiscard]] std::string kernel_symbol_apc_state() {
    return "ApcState";
}


[[nodiscard]] std::string kernel_type_kthread_for_process() {
    return "_KTHREAD";
}


[[nodiscard]] std::string kernel_symbol_process() {
    return "Process";
}


[[nodiscard]] std::string kernel_symbol_kapc_state() {
    return "_KAPC_STATE";
}


[[nodiscard]] std::string kernel_symbol_previous_mode() {
    return "PreviousMode";
}


[[nodiscard]] std::string kernel_type_kthread_for_trap_frame() {
    return "_KTHREAD";
}


[[nodiscard]] std::string kernel_symbol_trap_frame() {
    return "TrapFrame";
}


[[nodiscard]] std::string kernel_type_kthread_for_state() {
    return "_KTHREAD";
}


[[nodiscard]] std::string kernel_type_kthread_for_thread_list_head() {
    return "_KTHREAD";
}


[[nodiscard]] std::string kernel_symbol_thread_list_head() {
    return "ThreadListHead";
}


[[nodiscard]] std::string kernel_type_eprocess_for_thread_list_entry() {
    return "_EPROCESS";
}


[[nodiscard]] char* allocate_kernel_symbol_thread_list_entry(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("ThreadListEntry");
}


[[nodiscard]] char* allocate_kernel_symbol_ethread(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("_ETHREAD");
}


[[nodiscard]] char* allocate_kernel_symbol_rip(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Rip");
}


[[nodiscard]] std::string kernel_type_ktrap_frame_for_rip() {
    return "_KTRAP_FRAME";
}


[[nodiscard]] char* allocate_kernel_symbol_rsp(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Rsp");
}


[[nodiscard]] std::string kernel_type_ktrap_frame_for_rsp() {
    return "_KTRAP_FRAME";
}


[[nodiscard]] char* allocate_error_code_mk_3002(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-3002");
}


[[nodiscard]] char* allocate_please_launch_the_game_now_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Please launch the game now");
}


[[nodiscard]] char* allocate_waiting_for_game_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Waiting for game...");
}


[[nodiscard]] char* allocate_timed_out_waiting_for_game_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Timed out waiting for game");
}


[[nodiscard]] char* allocate_error_code_mk_4003(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-4003");
}


[[nodiscard]] char* allocate_injecting_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Injecting...");
}


[[nodiscard]] char* allocate_sleep_api_name(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Sleep");
}


[[nodiscard]] char* allocate_sleep_kernel32_module_name(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("kernel32.dll");
}


[[nodiscard]] char* allocate_target_process_not_found_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Target process not found");
}


[[nodiscard]] char* allocate_error_code_mk_4001(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-4001");
}


[[nodiscard]] char* allocate_target_process_kernel_info_not_found_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Target process kernel info not found");
}


[[nodiscard]] char* allocate_error_code_mk_4002(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-4002");
}


[[nodiscard]] char* allocate_error_code_mk_5001a(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-5001a");
}


[[nodiscard]] std::string ntstatus_hex_format_for_mk_5001a() {
    return "0x%08X";
}


[[nodiscard]] char* allocate_error_code_mk_5001b(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-5001b");
}


[[nodiscard]] std::string ntstatus_hex_format_for_mk_5001b() {
    return "0x%08X";
}


[[nodiscard]] char* allocate_error_code_mk_5001c(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-5001c");
}


[[nodiscard]] char* allocate_page_preparation_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Page preparation failed");
}


[[nodiscard]] std::string error_code_mk_5002_for_page_preparation() {
    return "MK-5002";
}


[[nodiscard]] std::string error_code_mk_5002_for_page_preparation_detail() {
    return "MK-5002";
}


[[nodiscard]] char* allocate_error_code_mk_6002(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-6002");
}


[[nodiscard]] std::string error_code_mk_6003_for_secondary_component_resolution() {
    return "MK-6003";
}


[[nodiscard]] char* allocate_component_resolution_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Component resolution failed");
}


[[nodiscard]] std::string error_code_mk_6003_for_component_resolution() {
    return "MK-6003";
}


[[nodiscard]] char* allocate_memory_write_failed_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Memory write failed");
}


[[nodiscard]] char* allocate_error_code_mk_5003(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-5003");
}


[[nodiscard]] char* allocate_no_suitable_execution_context_found_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("No suitable execution context found");
}


[[nodiscard]] char* allocate_error_code_mk_7001(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-7001");
}


[[nodiscard]] char* allocate_execution_timeout_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("Execution timeout");
}


[[nodiscard]] char* allocate_error_code_mk_7002(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("MK-7002");
}

}
