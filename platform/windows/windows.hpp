#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <windows.h>

namespace makima::platform::windows {

struct NativeJobInformationRequest final {
    HANDLE job{};
    std::uint64_t value{};
    void* owner{};
    std::uint32_t completed{};
};

struct WaitForSecurityEventRequest final {
    HANDLE object{};
    DWORD timeout{INFINITE};
    bool alertable{};
    DWORD result{WAIT_FAILED};
};

struct SecurityFailureContext final {
    std::uint32_t failure_class{};
    std::uint32_t flags{};
    DWORD error_code{};
    DWORD nt_status{};
    const char* module{};
    const char* function{};
    const char* call_context{};
    const wchar_t* message{};
    DWORD thread_id{};
};

[[nodiscard]] HMODULE load_dynamic_library(std::string_view module_name);


[[nodiscard]] char* allocate_shcore_ansi_module_name(
    const std::byte* protected_source);
[[nodiscard]] FARPROC resolve_named_export_from_module(
    HMODULE module,
    std::string_view export_name);
[[nodiscard]] FARPROC resolve_raise_fail_fast_exception(
    std::uint64_t lookup_flags) noexcept;
[[nodiscard]] FARPROC resolve_module_heap_release_routine(
    HMODULE module,
    std::string_view export_name);
[[nodiscard]] FARPROC resolve_first_module_heap_text_release(
    HMODULE module,
    std::string_view export_name);
[[nodiscard]] bool initialize_platform_api_bindings() noexcept;
[[nodiscard]] const char* get_current_ansi_module_file_path() noexcept;
[[nodiscard]] std::wstring get_wide_module_file_path_for_update_event(
    HMODULE module = nullptr);
[[nodiscard]] char* copy_ansi_module_file_path(
    char* destination,
    int* copied_length,
    HMODULE* module,
    std::size_t capacity) noexcept;
[[nodiscard]] bool find_pattern_in_loaded_image_sections(
    void* owner,
    const char* image_path,
    const void* pattern,
    std::uint32_t pattern_size,
    std::uint32_t* section_rva,
    std::uint32_t* section_size,
    std::uint32_t* section_index,
    std::uintptr_t* image_base) noexcept;

[[nodiscard]] HANDLE call_open_semaphore_w(
    std::wstring_view value,
    DWORD access = SYNCHRONIZE | SEMAPHORE_MODIFY_STATE);
[[nodiscard]] HANDLE call_create_semaphore_ex_w(
    std::wstring_view value,
    LONG initial_count,
    LONG maximum_count);
[[nodiscard]] bool call_release_semaphore(
    HANDLE semaphore,
    LONG release_count,
    LONG* previous_count = nullptr);
[[nodiscard]] std::uint64_t call_wait_for_single_object_ex(
    WaitForSecurityEventRequest* request) noexcept;
[[nodiscard]] bool call_nt_set_information_job_object(
    NativeJobInformationRequest* request) noexcept;
[[nodiscard]] std::uint64_t format_system_error_message(
    wchar_t* destination,
    std::size_t capacity,
    SecurityFailureContext* context) noexcept;

[[nodiscard]] HANDLE create_or_open_named_semaphore(
    std::wstring_view semaphore_name,
    LONG initial_count,
    LONG maximum_count);
[[nodiscard]] std::uint64_t acquire_named_process_mutex(
    const char* channel_name,
    HANDLE* semaphore_out) noexcept;

}
