#pragma once

#include "makima/platform/pe_mapping_plan.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace makima::process::pe_mapping {

using VirtualAddress = std::uintptr_t;

using VirtualQueryFunction = SIZE_T(WINAPI*)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
using CreateToolhelp32SnapshotFunction = HANDLE(WINAPI*)(DWORD, DWORD);
using Process32FirstWFunction = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using Process32NextWFunction = BOOL(WINAPI*)(HANDLE, LPPROCESSENTRY32W);
using LocalFreeFunction = HLOCAL(WINAPI*)(HLOCAL);

class MappingMetadata final {
public:
    void set_ready(bool ready = true) noexcept { ready_ = ready; }

    [[nodiscard]] bool ready() const noexcept { return ready_; }

    void set_integer(
        std::string section,
        std::string key,
        std::int32_t value) {
        integers_[std::move(section)].insert_or_assign(std::move(key), value);
    }

    [[nodiscard]] std::optional<std::int32_t> integer(
        std::string_view section,
        std::string_view key) const {
        const auto found_section = integers_.find(std::string{section});
        if (found_section == integers_.end()) {
            return std::nullopt;
        }
        const auto found_value = found_section->second.find(std::string{key});
        return found_value == found_section->second.end()
            ? std::nullopt
            : std::optional{found_value->second};
    }

private:
    bool ready_{};
    std::unordered_map<std::string, std::unordered_map<std::string, std::int32_t>> integers_;
};

struct ManualMapResult {
    VirtualAddress image_base{};
    VirtualAddress entry_point{};
    std::size_t imported_symbol_count{};
    std::size_t applied_relocation_count{};
    std::size_t invoked_tls_callback_count{};
    bool entry_point_succeeded{};
};

struct ProcessMatch {
    std::uint32_t process_id{};
    bool wow64{};
};

struct RemoteModule {
    VirtualAddress base{};
    std::uint32_t image_size{};
    std::wstring name;
    std::wstring path;
};

struct MappedImageMetadata {
    std::array<std::byte, 0x10> parser_state{};
    std::uint8_t headers_available{};
    std::array<std::byte, 0x0f> parser_padding{};
    const IMAGE_NT_HEADERS64* nt_headers{};
};

static_assert(offsetof(MappedImageMetadata, headers_available) == 0x10);
static_assert(offsetof(MappedImageMetadata, nt_headers) == 0x20);

class MappingError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] VirtualQueryFunction resolve_virtual_query_api();
[[nodiscard]] CreateToolhelp32SnapshotFunction resolve_create_toolhelp32_snapshot_api();
[[nodiscard]] Process32FirstWFunction resolve_process32_first_api();
[[nodiscard]] Process32NextWFunction resolve_process32_next_api();
[[nodiscard]] LocalFreeFunction resolve_local_free_api();


[[nodiscard]] MappingMetadata make_empty_mapping_metadata();
[[nodiscard]] std::int32_t read_mapping_metadata_integer(
    const MappingMetadata& metadata,
    const char* section,
    const char* key);
void format_mapper_message(
    std::span<char, 256> destination,
    const char* detail,
    const char* context) noexcept;
[[nodiscard]] const std::string& kernel_vad_root_field_name();

[[nodiscard]] char* allocate_kernel32_library_name_for_snapshot(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_process32_first_api_name(
    std::int64_t protected_source);
[[nodiscard]] std::string invalid_payload_message_for_buffer_validation();
[[nodiscard]] char* allocate_mm_unlock_pages_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_system_component_resolution_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_system_symbol_resolution_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_unique_process_id_field_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_eprocess_type_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_thread_state_field_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_system_offset_resolution_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_loading_into_target_process_status(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_memory_allocation_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_page_preparation_failure_detail_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_primary_component_resolution_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_secondary_component_resolution_failure_message(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_dynamic_library_filename_format(
    std::int64_t protected_source);

[[nodiscard]] FARPROC resolve_loaded_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_virtual_query_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_snapshot_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_process_first_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_process_next_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_local_free_export(
    const char* module_name,
    const char* symbol_name) noexcept;
[[nodiscard]] FARPROC resolve_sleep_export(
    const char* module_name,
    const char* symbol_name) noexcept;

[[nodiscard]] std::wstring widen_process_name(std::string_view process_name);
[[nodiscard]] std::optional<ProcessMatch> find_process_by_name(std::wstring_view process_name);
[[nodiscard]] std::optional<RemoteModule> find_remote_module(
    std::uint32_t process_id,
    std::wstring_view module_name);
[[nodiscard]] std::optional<RemoteModule> find_remote_module_by_index(
    std::uint32_t process_id,
    std::size_t module_index);

[[nodiscard]] VirtualAddress resolve_remote_export(
    std::uint32_t process_id,
    const RemoteModule& module,
    std::string_view symbol_name);
[[nodiscard]] VirtualAddress resolve_remote_export_ordinal(
    std::uint32_t process_id,
    const RemoteModule& module,
    std::uint16_t ordinal);

[[nodiscard]] ManualMapResult manual_map_pe_dll(
    std::uint32_t process_id,
    std::span<const std::uint8_t> portable_executable);

[[nodiscard]] std::uint16_t get_mapped_image_subsystem(
    const MappedImageMetadata& image) noexcept;

}
