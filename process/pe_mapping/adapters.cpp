#include "process/pe_mapping/pe_mapping.hpp"
#include "process/pe_mapping/memory.hpp"
#include "process/pe_mapping/text_cache.hpp"
#include "security/anti_analysis/anti_analysis.hpp"

#include <cstdio>
#include <array>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <string_view>

namespace makima::process::pe_mapping {
namespace decoded = makima::process::pe_mapping::literals;

namespace {

std::string make_close_game_before_loading_message() {
    static constexpr std::array<char, 37> bytes{
        'P', 'l', 'e', 'a', 's', 'e', ' ', 'c', 'l', 'o', 's', 'e', ' ',
        't', 'h', 'e', ' ', 'g', 'a', 'm', 'e', ' ', 'b', 'e', 'f', 'o',
        'r', 'e', ' ', 'l', 'o', 'a', 'd', 'i', 'n', 'g', '\0'};
    return std::string{bytes.data(), bytes.size() - 1U};
}

std::string make_game_still_running_error_code() {
    static constexpr std::array<char, 8> bytes{
        'M', 'K', '-', '1', '0', '0', '1', '\0'};
    return std::string{bytes.data(), bytes.size() - 1U};
}

template <std::size_t Extent>
[[nodiscard]] char* allocate_narrow_literal(const char (&literal)[Extent]) {
    auto* output = static_cast<char*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}

}


void abort_virtual_query_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7048ULL);
}

void abort_kernel32_library_name_for_snapshot_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7058ULL);
}

const std::string& get_stack_frame_resides_in_page_execute_readwrite_memory_message() {
    return mapping_text_cache().narrow(0x1414E7068ULL, decoded::stack_frame_resides_in_page_execute_readwrite_memory_message);
}

void abort_stack_frame_resides_in_page_execute_readwrite_memory_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7068ULL);
}

const std::string& get_anti_tamper_rwx_frame_event_name() {
    return mapping_text_cache().narrow(0x1414E7078ULL, decoded::anti_tamper_rwx_frame_event_name);
}

void abort_anti_tamper_rwx_frame_event_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7078ULL);
}

const std::string& get_stack_frame_resides_in_page_execute_writecopy_memory_message() {
    return mapping_text_cache().narrow(0x1414E7088ULL, decoded::stack_frame_resides_in_page_execute_writecopy_memory_message);
}

void abort_stack_frame_resides_in_page_execute_writecopy_memory_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7088ULL);
}

const std::string& get_anti_tamper_executable_writecopy_frame_event_name() {
    return mapping_text_cache().narrow(0x1414E7098ULL, decoded::anti_tamper_executable_writecopy_frame_event_name);
}

void abort_anti_tamper_executable_writecopy_frame_event_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7098ULL);
}


std::uint16_t get_mapped_image_subsystem(const MappedImageMetadata& image) noexcept {
    return image.headers_available == 1U
        ? image.nt_headers->OptionalHeader.Subsystem
        : IMAGE_SUBSYSTEM_UNKNOWN;
}

void abort_process_enumerator_slot_2_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7168ULL);
}

void abort_process_enumerator_slot_3_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7178ULL);
}

void abort_process_enumerator_slot_4_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7188ULL);
}

void abort_process_enumerator_slot_5_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7198ULL);
}

void abort_process_enumerator_slot_6_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E71A8ULL);
}

void abort_process_enumerator_slot_7_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E71B8ULL);
}

void abort_process_enumerator_slot_8_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E71C8ULL);
}

void abort_is_wow64_process_api_name_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7148ULL);
}

void abort_wow64_query_kernel32_module_name_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7158ULL);
}

void abort_process_enumerator_slot_9_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E71D8ULL);
}

void abort_create_toolhelp32_snapshot_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7308ULL);
}

void abort_toolhelp_snapshot_kernel32_module_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7318ULL);
}

void abort_process32_first_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7328ULL);
}

void abort_process_enumeration_kernel32_module_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7338ULL);
}

void abort_process32_next_w_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7348ULL);
}

void abort_process_next_kernel32_module_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7358ULL);
}

void abort_local_free_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7368ULL);
}

void abort_local_free_kernel32_module_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7378ULL);
}

void abort_destiny2_target_name_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7388ULL);
}

void abort_warframe_target_name_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7398ULL);
}


void format_mapper_message(
    std::span<char, 256> destination,
    const char* detail,
    const char* context) noexcept {
    const auto& format = mapping_text_cache().narrow(
        0x1414E73A8ULL, decoded::message_with_code_format);
    const int written = std::snprintf(
        destination.data(), destination.size(), format.c_str(),
        context != nullptr ? context : "",
        detail != nullptr ? detail : "");
    if (written < 0) {
        destination.front() = '\0';
    }
}

void abort_message_with_code_format_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

void abort_invalid_payload_message_for_buffer_validation_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73B8ULL);
}

void abort_error_code_mk_1002_for_buffer_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73C8ULL);
}

void abort_message_format_after_buffer_validation() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

void abort_invalid_payload_message_for_dos_header_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73D8ULL);
}

void abort_error_code_mk_1002_for_dos_header_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73E8ULL);
}

void abort_message_format_after_dos_header_validation() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

void abort_invalid_payload_message_for_nt_header_bounds_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73F8ULL);
}

void abort_error_code_mk_1002_for_nt_header_bounds_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7408ULL);
}

void abort_message_format_after_nt_header_bounds_validation() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

void abort_invalid_payload_message_for_pe_signature_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7418ULL);
}

void abort_error_code_mk_1002_for_pe_signature_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7428ULL);
}

void abort_message_format_after_pe_signature_validation() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

void abort_invalid_payload_format_for_dll_characteristics_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7438ULL);
}

void abort_error_code_mk_1002_for_dll_characteristics_validation_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7448ULL);
}

void abort_message_format_after_dll_characteristics_validation() noexcept {
    mapping_text_cache().abort_initialization(0x1414E73A8ULL);
}

const std::string& get_close_game_before_loading_message() {
    return mapping_text_cache().narrow(
        0x1414E7458ULL,
        make_close_game_before_loading_message);
}

void abort_close_game_before_loading_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7458ULL);
}

const std::string& get_game_still_running_error_code() {
    return mapping_text_cache().narrow(
        0x1414E7468ULL,
        make_game_still_running_error_code);
}

void abort_game_still_running_error_code_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7468ULL);
}

const std::string& get_initialization_failed_message_for_mk_2001() {
    return mapping_text_cache().narrow(0x1414E7488ULL, decoded::initialization_failed_message_for_mk_2001);
}

void abort_initialization_failed_message_for_mk_2001_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7488ULL);
}

const std::string& get_error_code_mk_2001() {
    return mapping_text_cache().narrow(0x1414E7498ULL, decoded::error_code_mk_2001);
}

void abort_error_code_mk_2001_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7498ULL);
}

const std::string& get_initialization_failed_message_for_mk_2002() {
    return mapping_text_cache().narrow(0x1414E74A8ULL, decoded::initialization_failed_message_for_mk_2002);
}

void abort_initialization_failed_message_for_mk_2002_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74A8ULL);
}

const std::string& get_error_code_mk_2002() {
    return mapping_text_cache().narrow(0x1414E74B8ULL, decoded::error_code_mk_2002);
}

void abort_error_code_mk_2002_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74B8ULL);
}

const std::string& get_kernel_hyperspace_ready_message() {
    return mapping_text_cache().narrow(0x1414E74C8ULL, decoded::kernel_hyperspace_ready_message);
}

void abort_kernel_hyperspace_ready_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74C8ULL);
}

const std::string& get_initializing_message() {
    return mapping_text_cache().narrow(0x1414E74D8ULL, decoded::initializing_message);
}

void abort_initializing_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74D8ULL);
}

const std::string& get_ex_allocate_pool_with_tag_api_name() {
    return mapping_text_cache().narrow(0x1414E74E8ULL, decoded::ex_allocate_pool_with_tag_api_name);
}

void abort_ex_allocate_pool_with_tag_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74E8ULL);
}

const std::string& get_ex_free_pool_with_tag_api_name() {
    return mapping_text_cache().narrow(0x1414E74F8ULL, decoded::ex_free_pool_with_tag_api_name);
}

void abort_ex_free_pool_with_tag_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E74F8ULL);
}

const std::string& get_io_allocate_mdl_api_name() {
    return mapping_text_cache().narrow(0x1414E7508ULL, decoded::io_allocate_mdl_api_name);
}

void abort_io_allocate_mdl_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7508ULL);
}

const std::string& get_io_free_mdl_api_name() {
    return mapping_text_cache().narrow(0x1414E7518ULL, decoded::io_free_mdl_api_name);
}

void abort_io_free_mdl_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7518ULL);
}

const std::string& get_mm_probe_and_lock_process_pages_api_name() {
    return mapping_text_cache().narrow(0x1414E7528ULL, decoded::mm_probe_and_lock_process_pages_api_name);
}

void abort_mm_probe_and_lock_process_pages_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7528ULL);
}

const std::string& get_mm_unlock_pages_api_name() {
    return mapping_text_cache().narrow(
        0x1414E7538ULL,
        [] { return allocate_mm_unlock_pages_api_name(0x1414D9B9FLL); });
}

void abort_mm_unlock_pages_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7538ULL);
}

const std::string& get_zw_allocate_virtual_memory_api_name() {
    return mapping_text_cache().narrow(0x1414E7548ULL, decoded::zw_allocate_virtual_memory_api_name);
}

void abort_zw_allocate_virtual_memory_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7548ULL);
}

const std::string& get_zw_close_api_name() {
    return mapping_text_cache().narrow(0x1414E7558ULL, decoded::zw_close_api_name);
}

void abort_zw_close_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7558ULL);
}

const std::string& get_zw_protect_virtual_memory_api_name() {
    return mapping_text_cache().narrow(0x1414E7568ULL, decoded::zw_protect_virtual_memory_api_name);
}

void abort_zw_protect_virtual_memory_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7568ULL);
}

const std::string& get_ob_open_object_by_pointer_api_name() {
    return mapping_text_cache().narrow(0x1414E7578ULL, decoded::ob_open_object_by_pointer_api_name);
}

void abort_ob_open_object_by_pointer_api_name_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7578ULL);
}

const std::string& get_kernel_symbol_ps_process_type() {
    return mapping_text_cache().narrow(0x1414E7588ULL, decoded::kernel_symbol_ps_process_type);
}

void abort_kernel_symbol_ps_process_type_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7588ULL);
}

const std::string& get_system_component_resolution_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E7598ULL,
        [] { return allocate_system_component_resolution_failure_message(0x1414D9C0ELL); });
}

void abort_system_component_resolution_failure_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7598ULL);
}

const std::string& get_error_code_mk_3003() {
    return mapping_text_cache().narrow(0x1414E75A8ULL, decoded::error_code_mk_3003);
}

void abort_error_code_mk_3003_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E75A8ULL);
}

const std::string& get_system_symbol_resolution_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E75B8ULL,
        [] { return allocate_system_symbol_resolution_failure_message(0x1414D9C3BLL); });
}

void abort_system_symbol_resolution_failure_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E75B8ULL);
}

const std::string& get_error_code_mk_3001() {
    return mapping_text_cache().narrow(0x1414E75C8ULL, decoded::error_code_mk_3001);
}

void abort_error_code_mk_3001_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E75C8ULL);
}

const std::string& get_unique_process_id_field_name() {
    return mapping_text_cache().narrow(
        0x1414E75D8ULL,
        [] { return allocate_unique_process_id_field_name(0x1414D9C65LL); });
}

const std::string& get_kernel_type_eprocess_for_active_process_links() {
    return mapping_text_cache().narrow(0x1414E75E8ULL, decoded::kernel_type_eprocess_for_active_process_links);
}

const std::string& get_kernel_symbol_active_process_links() {
    return mapping_text_cache().narrow(0x1414E75F8ULL, decoded::kernel_symbol_active_process_links);
}

const std::string& get_eprocess_type_name() {
    return mapping_text_cache().narrow(
        0x1414E7608ULL,
        [] { return allocate_eprocess_type_name(0x1414D9C95LL); });
}

const std::string& get_kernel_symbol_image_file_name() {
    return mapping_text_cache().narrow(0x1414E7618ULL, decoded::kernel_symbol_image_file_name);
}

const std::string& get_kernel_type_eprocess_for_directory_table_base() {
    return mapping_text_cache().narrow(0x1414E7628ULL, decoded::kernel_type_eprocess_for_directory_table_base);
}

const std::string& get_kernel_symbol_directory_table_base() {
    return mapping_text_cache().narrow(0x1414E7638ULL, decoded::kernel_symbol_directory_table_base);
}

const std::string& get_kernel_symbol_kprocess() {
    return mapping_text_cache().narrow(0x1414E7648ULL, decoded::kernel_symbol_kprocess);
}

const std::string& get_kernel_symbol_peb() {
    return mapping_text_cache().narrow(0x1414E7658ULL, decoded::kernel_symbol_peb);
}

const std::string& get_kernel_type_eprocess_for_vad_root() {
    return mapping_text_cache().narrow(0x1414E7668ULL, decoded::kernel_type_eprocess_for_vad_root);
}

const std::string& get_kernel_type_eprocess_for_apc_state() {
    return mapping_text_cache().narrow(0x1414E7688ULL, decoded::kernel_type_eprocess_for_apc_state);
}

const std::string& get_kernel_symbol_apc_state() {
    return mapping_text_cache().narrow(0x1414E7698ULL, decoded::kernel_symbol_apc_state);
}

const std::string& get_kernel_type_kthread_for_process() {
    return mapping_text_cache().narrow(0x1414E76A8ULL, decoded::kernel_type_kthread_for_process);
}

const std::string& get_kernel_symbol_process() {
    return mapping_text_cache().narrow(0x1414E76B8ULL, decoded::kernel_symbol_process);
}

const std::string& get_kernel_symbol_kapc_state() {
    return mapping_text_cache().narrow(0x1414E76C8ULL, decoded::kernel_symbol_kapc_state);
}

const std::string& get_kernel_symbol_previous_mode() {
    return mapping_text_cache().narrow(0x1414E76D8ULL, decoded::kernel_symbol_previous_mode);
}

const std::string& get_kernel_type_kthread_for_trap_frame() {
    return mapping_text_cache().narrow(0x1414E76E8ULL, decoded::kernel_type_kthread_for_trap_frame);
}

const std::string& get_kernel_symbol_trap_frame() {
    return mapping_text_cache().narrow(0x1414E76F8ULL, decoded::kernel_symbol_trap_frame);
}

const std::string& get_kernel_type_kthread_for_state() {
    return mapping_text_cache().narrow(0x1414E7708ULL, decoded::kernel_type_kthread_for_state);
}

const std::string& get_thread_state_field_name() {
    return mapping_text_cache().narrow(
        0x1414E7718ULL,
        [] { return allocate_thread_state_field_name(0x1414D9D54LL); });
}

const std::string& get_kernel_type_kthread_for_thread_list_head() {
    return mapping_text_cache().narrow(0x1414E7728ULL, decoded::kernel_type_kthread_for_thread_list_head);
}

const std::string& get_kernel_symbol_thread_list_head() {
    return mapping_text_cache().narrow(0x1414E7738ULL, decoded::kernel_symbol_thread_list_head);
}

const std::string& get_kernel_type_eprocess_for_thread_list_entry() {
    return mapping_text_cache().narrow(0x1414E7748ULL, decoded::kernel_type_eprocess_for_thread_list_entry);
}

const std::string& get_kernel_symbol_thread_list_entry() {
    return mapping_text_cache().narrow(
        0x1414E7758ULL,
        [] { return decoded::allocate_kernel_symbol_thread_list_entry(0x1414D9D80LL); });
}

const std::string& get_kernel_symbol_ethread() {
    return mapping_text_cache().narrow(
        0x1414E7768ULL,
        [] { return decoded::allocate_kernel_symbol_ethread(0x1414D9D91LL); });
}

const std::string& get_kernel_symbol_rip() {
    return mapping_text_cache().narrow(
        0x1414E7778ULL,
        [] { return decoded::allocate_kernel_symbol_rip(0x1414D9D9BLL); });
}

const std::string& get_kernel_type_ktrap_frame_for_rip() {
    return mapping_text_cache().narrow(0x1414E7788ULL, decoded::kernel_type_ktrap_frame_for_rip);
}

const std::string& get_kernel_symbol_rsp() {
    return mapping_text_cache().narrow(
        0x1414E7798ULL,
        [] { return decoded::allocate_kernel_symbol_rsp(0x1414D9DAELL); });
}

const std::string& get_kernel_type_ktrap_frame_for_rsp() {
    return mapping_text_cache().narrow(0x1414E77A8ULL, decoded::kernel_type_ktrap_frame_for_rsp);
}

const std::string& get_system_offset_resolution_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E77B8ULL,
        [] { return allocate_system_offset_resolution_failure_message(0x1414D9DC1LL); });
}

const std::string& get_error_code_mk_3002() {
    return mapping_text_cache().narrow(
        0x1414E77C8ULL,
        [] { return decoded::allocate_error_code_mk_3002(0x1414D9DE2LL); });
}

const std::string& get_please_launch_the_game_now_message() {
    return mapping_text_cache().narrow(
        0x1414E77D8ULL,
        [] { return decoded::allocate_please_launch_the_game_now_message(0x1414D9DEBLL); });
}

const std::string& get_waiting_for_game_message() {
    return mapping_text_cache().narrow(
        0x1414E77E8ULL,
        [] { return decoded::allocate_waiting_for_game_message(0x1414D9E07LL); });
}

const std::string& get_timed_out_waiting_for_game_message() {
    return mapping_text_cache().narrow(
        0x1414E7878ULL,
        [] { return decoded::allocate_timed_out_waiting_for_game_message(0x1414D9E8DLL); });
}

const std::string& get_error_code_mk_4003() {
    return mapping_text_cache().narrow(
        0x1414E7888ULL,
        [] { return decoded::allocate_error_code_mk_4003(0x1414D9EA9LL); });
}

const std::string& get_loading_into_target_process_status() {
    return mapping_text_cache().narrow(
        0x1414E7898ULL,
        [] { return allocate_loading_into_target_process_status(0x1414D9EB2LL); });
}

const std::string& get_injecting_message() {
    return mapping_text_cache().narrow(
        0x1414E78A8ULL,
        [] { return decoded::allocate_injecting_message(0x1414D9ECFLL); });
}

const std::string& get_sleep_api_name() {
    return mapping_text_cache().narrow(
        0x1414E78B8ULL,
        [] { return decoded::allocate_sleep_api_name(0x1414D9EDDLL); });
}

const std::string& get_sleep_kernel32_module_name() {
    return mapping_text_cache().narrow(
        0x1414E78C8ULL,
        [] { return decoded::allocate_sleep_kernel32_module_name(0x1414D9EE4LL); });
}

const std::string& get_target_process_not_found_message() {
    return mapping_text_cache().narrow(
        0x1414E78D8ULL,
        [] { return decoded::allocate_target_process_not_found_message(0x1414D9EF2LL); });
}

const std::string& get_error_code_mk_4001() {
    return mapping_text_cache().narrow(
        0x1414E78E8ULL,
        [] { return decoded::allocate_error_code_mk_4001(0x1414D9F0CLL); });
}

const std::string& get_target_process_kernel_info_not_found_message() {
    return mapping_text_cache().narrow(
        0x1414E78F8ULL,
        [] { return decoded::allocate_target_process_kernel_info_not_found_message(0x1414D9F15LL); });
}

const std::string& get_error_code_mk_4002() {
    return mapping_text_cache().narrow(
        0x1414E7908ULL,
        [] { return decoded::allocate_error_code_mk_4002(0x1414D9F3BLL); });
}

const std::string& get_memory_allocation_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E7918ULL,
        [] { return allocate_memory_allocation_failure_message(0x1414D9F44LL); });
}

const std::string& get_error_code_mk_5001a() {
    return mapping_text_cache().narrow(
        0x1414E7928ULL,
        [] { return decoded::allocate_error_code_mk_5001a(0x1414D9F5ELL); });
}

const std::string& get_ntstatus_hex_format_for_mk_5001a() {
    return mapping_text_cache().narrow(0x1414E7938ULL, decoded::ntstatus_hex_format_for_mk_5001a);
}

const std::string& get_error_code_mk_5001b() {
    return mapping_text_cache().narrow(
        0x1414E7948ULL,
        [] { return decoded::allocate_error_code_mk_5001b(0x1414D9F70LL); });
}

const std::string& get_ntstatus_hex_format_for_mk_5001b() {
    return mapping_text_cache().narrow(0x1414E7958ULL, decoded::ntstatus_hex_format_for_mk_5001b);
}

const std::string& get_error_code_mk_5001c() {
    return mapping_text_cache().narrow(
        0x1414E7968ULL,
        [] { return decoded::allocate_error_code_mk_5001c(0x1414D9F82LL); });
}

void abort_error_code_mk_5001c_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7968ULL);
}

const std::string& get_page_preparation_failed_message() {
    return mapping_text_cache().narrow(
        0x1414E7978ULL,
        [] { return decoded::allocate_page_preparation_failed_message(0x1414D9F8CLL); });
}

void abort_page_preparation_failed_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7978ULL);
}

const std::string& get_error_code_mk_5002_for_page_preparation() {
    return mapping_text_cache().narrow(0x1414E7988ULL, decoded::error_code_mk_5002_for_page_preparation);
}

void abort_error_code_mk_5002_for_page_preparation_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7988ULL);
}

const std::string& get_page_preparation_failure_detail_message() {
    return mapping_text_cache().narrow(
        0x1414E7998ULL,
        [] { return allocate_page_preparation_failure_detail_message(0x1414D9FAELL); });
}

void abort_page_preparation_failure_detail_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7998ULL);
}

const std::string& get_error_code_mk_5002_for_page_preparation_detail() {
    return mapping_text_cache().narrow(0x1414E79A8ULL, decoded::error_code_mk_5002_for_page_preparation_detail);
}

void abort_error_code_mk_5002_for_page_preparation_detail_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79A8ULL);
}

const std::string& get_primary_component_resolution_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E79B8ULL,
        [] { return allocate_primary_component_resolution_failure_message(0x1414D9FD0LL); });
}

void abort_primary_component_resolution_failure_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79B8ULL);
}

const std::string& get_error_code_mk_6002() {
    return mapping_text_cache().narrow(
        0x1414E79C8ULL,
        [] { return decoded::allocate_error_code_mk_6002(0x1414D9FEDLL); });
}

void abort_error_code_mk_6002_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79C8ULL);
}

const std::string& get_secondary_component_resolution_failure_message() {
    return mapping_text_cache().narrow(
        0x1414E79D8ULL,
        [] { return allocate_secondary_component_resolution_failure_message(0x1414D9FF6LL); });
}

void abort_secondary_component_resolution_failure_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79D8ULL);
}

const std::string& get_error_code_mk_6003_for_secondary_component_resolution() {
    return mapping_text_cache().narrow(0x1414E79E8ULL, decoded::error_code_mk_6003_for_secondary_component_resolution);
}

void abort_error_code_mk_6003_for_secondary_component_resolution_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79E8ULL);
}

void abort_dynamic_library_filename_format_initialization() noexcept {
    mapping_text_cache().abort_initialization(0x1414E79F8ULL);
}

const std::string& get_component_resolution_failed_message() {
    return mapping_text_cache().narrow(
        0x1414E7A08ULL,
        [] { return decoded::allocate_component_resolution_failed_message(0x1414DA024LL); });
}

void abort_component_resolution_failed_message_cache() noexcept {
    mapping_text_cache().abort_initialization(0x1414E7A08ULL);
}

const std::string& get_error_code_mk_6003_for_component_resolution() {
    return mapping_text_cache().narrow(0x1414E7A18ULL, decoded::error_code_mk_6003_for_component_resolution);
}

const std::string& get_memory_write_failed_message() {
    return mapping_text_cache().narrow(
        0x1414E7A28ULL,
        [] { return decoded::allocate_memory_write_failed_message(0x1414DA04ALL); });
}

const std::string& get_error_code_mk_5003() {
    return mapping_text_cache().narrow(
        0x1414E7A38ULL,
        [] { return decoded::allocate_error_code_mk_5003(0x1414DA05FLL); });
}

const std::string& get_no_suitable_execution_context_found_message() {
    return mapping_text_cache().narrow(
        0x1414E7A48ULL,
        [] { return decoded::allocate_no_suitable_execution_context_found_message(0x1414DA068LL); });
}

const std::string& get_error_code_mk_7001() {
    return mapping_text_cache().narrow(
        0x1414E7A58ULL,
        [] { return decoded::allocate_error_code_mk_7001(0x1414DA08DLL); });
}

const std::string& get_execution_timeout_message() {
    return mapping_text_cache().narrow(
        0x1414E7A68ULL,
        [] { return decoded::allocate_execution_timeout_message(0x1414DA096LL); });
}

const std::string& get_error_code_mk_7002() {
    return mapping_text_cache().narrow(
        0x1414E7A78ULL,
        [] { return decoded::allocate_error_code_mk_7002(0x1414DA0A9LL); });
}

MappingMetadata make_empty_mapping_metadata() {
    return {};
}

char* allocate_eprocess_type_name(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("_EPROCESS");
}

char* allocate_thread_state_field_name(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("State");
}

char* allocate_dynamic_library_filename_format(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("%s.dll");
}


std::int32_t read_mapping_metadata_integer(
    const MappingMetadata& metadata,
    const char* section,
    const char* key) {
    if (!metadata.ready() || section == nullptr || *section == '\0' ||
        key == nullptr || *key == '\0') {
        return -1;
    }
    return metadata.integer(section, key).value_or(-1);
}

char* allocate_kernel32_library_name_for_snapshot(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("kernel32.dll");
}

char* allocate_system_offset_resolution_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("System offset resolution failed");
}

char* allocate_process32_first_api_name(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Process32FirstW");
}

std::string invalid_payload_message_for_buffer_validation() {

    return "Invalid payload";
}

char* allocate_mm_unlock_pages_api_name(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("MmUnlockPages");
}

char* allocate_system_component_resolution_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("System component resolution failed");
}

char* allocate_system_symbol_resolution_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("System symbol resolution failed");
}

char* allocate_unique_process_id_field_name(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("UniqueProcessId");
}

char* allocate_loading_into_target_process_status(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Loading into target process");
}

char* allocate_page_preparation_failure_detail_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Page preparation failed");
}

char* allocate_primary_component_resolution_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Component resolution failed");
}

char* allocate_secondary_component_resolution_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Component resolution failed");
}

char* allocate_memory_allocation_failure_message(std::int64_t protected_source) {
    (void)protected_source;

    return allocate_narrow_literal("Memory allocation failed");
}

}

namespace makima::security::anti_analysis {






wchar_t* allocate_secondary_search_host_executable_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"SearchHost.exe";
    static_assert(sizeof(decoded_value) == 30U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return output;
}

}
