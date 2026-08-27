#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace makima::storage::services {

using GetCurrentProcessFunction = HANDLE(WINAPI*)();



extern GetCurrentProcessFunction resolved_get_current_process;
void initialize_get_current_process_import() noexcept;

[[nodiscard]] char* allocate_lookup_privilege_value_w_import(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_delete_service_import(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_advapi32_for_delete_service(
    const std::uint8_t* protected_source);

[[nodiscard]] char* allocate_advapi32_dll(std::int64_t protected_source);
[[nodiscard]] char* allocate_adjust_token_privileges(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_advapi32_dll_for_adjust_token_privileges(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_open_scmanager_w(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_advapi32_dll_for_open_scmanager_w(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_open_service_w(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_advapi32_dll_for_open_service_w(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_control_service(std::int64_t protected_source);
[[nodiscard]] char* allocate_advapi32_dll_for_control_service(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_close_service_handle(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_advapi32_dll_for_close_service_handle(
    std::int64_t protected_source);
[[nodiscard]] wchar_t* allocate_winmeminfo_service_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_winmeminfo_driver_path(
    std::uint64_t protected_source);
[[nodiscard]] char* allocate_local_alloc_failed(
    std::int64_t protected_source);

struct ServiceSnapshot {
    std::wstring name;
    unsigned long state{};
    unsigned long start_type{};
    bool present{};
};

[[nodiscard]] ServiceSnapshot query_service(std::wstring_view name) noexcept;
[[nodiscard]] bool configure_service_start(
    std::wstring_view name,
    unsigned long start_type) noexcept;
[[nodiscard]] bool stop_service(std::wstring_view name, unsigned long timeout_ms) noexcept;
[[nodiscard]] std::vector<std::wstring> enumerate_dependent_services(std::wstring_view name);
[[nodiscard]] std::uint64_t resolve_mapped_image_imports(
    char* error_buffer,
    std::int64_t image_base,
    HMODULE(WINAPI* load_library)(LPCSTR),
    FARPROC(WINAPI* get_proc_address)(HMODULE, LPCSTR)) noexcept;
[[nodiscard]] void* resolve_case_folded_service_module_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_ascii_folded_service_library_symbol(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_normalized_service_module_exact_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_lowercase_service_library_export_hash(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_folded_service_module_verbatim_symbol(
    const char* module_name,
    const char* export_name) noexcept;

void clear_service_snapshot(ServiceSnapshot& snapshot) noexcept;
void remove_winmeminfo_service_and_driver() noexcept;

}
