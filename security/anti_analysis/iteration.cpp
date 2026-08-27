#include "security/anti_analysis/anti_analysis.hpp"
#include "security/environment/environment.hpp"

#include <windows.h>
#include <winternl.h>

#include <intrin.h>
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <cwctype>

namespace makima::security::anti_analysis {

namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

struct LoaderEntryView {
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
    LIST_ENTRY in_initialization_order;
    void* image_base;
    void* entry_point;
    ULONG image_size;
    ULONG padding;
    UNICODE_STRING full_image_name;
};

struct PebLoaderView {
    ULONG length;
    BOOLEAN initialized;
    unsigned char padding[3];
    void* loader_handle;
    LIST_ENTRY in_load_order;
    LIST_ENTRY in_memory_order;
};

const wchar_t* file_name_part(const wchar_t* path) noexcept {
    const wchar_t* file = path;
    for (const wchar_t* cursor = path; *cursor != L'\0'; ++cursor) {
        if (*cursor == L'/' || *cursor == L'\\') file = cursor + 1;
    }
    return file;
}

bool has_jump_prologue(const unsigned char* address) noexcept {
    return address != nullptr &&
        (address[0] == 0xe9 || address[0] == 0xeb || address[0] == 0xff);
}

const std::byte* second_in_load_order_image_base() noexcept {
    const auto* peb = reinterpret_cast<const std::byte*>(__readgsqword(0x60));
    if (peb == nullptr) return nullptr;

    PebLoaderView* loader{};
    std::memcpy(&loader, peb + 0x18, sizeof(loader));
    if (loader == nullptr) return nullptr;

    const LIST_ENTRY* const head = &loader->in_load_order;
    const LIST_ENTRY* first = head->Flink;
    if (first == nullptr || first == head) return nullptr;
    const LIST_ENTRY* second = first->Flink;
    if (second == nullptr || second == head) return nullptr;

    const auto* entry = reinterpret_cast<const LoaderEntryView*>(second);
    return static_cast<const std::byte*>(entry->image_base);
}

}






std::uint64_t parent_process_image_is_allowed() noexcept {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_process = ntdll == nullptr ? nullptr :
        reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query_process == nullptr) return 1;

    PROCESS_BASIC_INFORMATION information{};
    if (query_process(
            GetCurrentProcess(), ProcessBasicInformation,
            &information, sizeof(information), nullptr) < 0) {
        return 1;
    }

    const DWORD parent_id = static_cast<DWORD>(
        reinterpret_cast<std::uintptr_t>(information.Reserved3));
    const HANDLE parent = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_id);
    if (parent == nullptr) return 1;

    std::array<wchar_t, 0x104> image{};
    DWORD length = static_cast<DWORD>(image.size());
    QueryFullProcessImageNameW(parent, 0, image.data(), &length);
    CloseHandle(parent);










    static const wchar_t* const explorer = allocate_explorer_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB698ull));
    static const wchar_t* const svchost = allocate_svchost_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB6B4ull));
    static const wchar_t* const sihost = allocate_sihost_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB6CEull));
    static const wchar_t* const userinit =
        allocate_userinit_executable_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DB6E6ull));
    static const wchar_t* const runtime_broker =
        allocate_runtime_broker_exe(0x1414DB702ll);
    static const wchar_t* const secondary_search_host =
        allocate_secondary_search_host_executable_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DB728ull));
    static const wchar_t* const shell_experience_host =
        allocate_shell_experience_host_exe(0x1414DB748ll);
    static const wchar_t* const application_frame_host =
        allocate_application_frame_host_exe(0x1414DB77All);
    static const wchar_t* const command_prompt = allocate_cmd_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB7AEull));

    const std::array<const wchar_t*, 31> allowed{{
        explorer,
        svchost,
        sihost,
        userinit,
        runtime_broker,
        secondary_search_host,
        shell_experience_host,
        application_frame_host,
        command_prompt,
        powershell_image_name(),
        pwsh_image_name(),
        windows_terminal_image_name(),
        terminal_host_image_name(),
        wt_image_name(),
        chrome_image_name(),
        edge_image_name(),
        firefox_image_name(),
        opera_image_name(),
        brave_image_name(),
        vivaldi_image_name(),
        internet_explorer_image_name(),
        seven_zip_file_manager_image_name(),
        winrar_image_name(),
        total_commander_image_name(),
        discord_image_name(),
        discord_ptb_image_name(),
        discord_canary_image_name(),
        telegram_image_name(),
        rundll32_image_name(),
        task_manager_image_name(),
        dll_host_image_name()}};
    const wchar_t* base_name = file_name_part(image.data());
    return std::any_of(
        allowed.begin(), allowed.end(),
        [base_name](const wchar_t* candidate) {
            return _wcsicmp(base_name, candidate) == 0;
        }) ? 1 : 0;
}



std::uint64_t loaded_module_names_are_clean_from_peb() noexcept {
    const auto* peb = reinterpret_cast<const std::byte*>(__readgsqword(0x60));
    if (peb == nullptr) return 1;
    PebLoaderView* loader{};
    std::memcpy(&loader, peb + 0x18, sizeof(loader));
    if (loader == nullptr) return 1;

    const LIST_ENTRY* const head = &loader->in_memory_order;
    const LIST_ENTRY* node = head->Flink;
    for (std::size_t visited = 0;
         node != nullptr && node != head && visited != 0xfff;
         node = node->Flink, ++visited) {
        const auto* entry = reinterpret_cast<const LoaderEntryView*>(
            reinterpret_cast<const std::byte*>(node) -
            offsetof(LoaderEntryView, in_memory_order));
        if (entry->full_image_name.Buffer == nullptr ||
            entry->full_image_name.Length < sizeof(wchar_t)) {
            continue;
        }

        std::array<wchar_t, 0x104> lowered{};
        const std::size_t count = (std::min)(
            static_cast<std::size_t>(
                entry->full_image_name.Length / sizeof(wchar_t)),
            lowered.size() - 1);
        for (std::size_t index = 0; index != count; ++index) {
            const wchar_t value = entry->full_image_name.Buffer[index];
            lowered[index] = value >= L'A' && value <= L'Z'
                ? static_cast<wchar_t>(value | 0x20)
                : value;
        }



        static const wchar_t* const cheat_engine =
            makima::security::environment::
                allocate_module_scan_cheat_engine_token(
                    reinterpret_cast<const std::uint16_t*>(
                        0x1414DBEDCull));
        if (std::wcsstr(lowered.data(), cheat_engine) != nullptr) return 0;

        static const wchar_t* const speedhack =
            makima::security::environment::
                allocate_module_scan_speedhack_token(
                    reinterpret_cast<const std::uint16_t*>(
                        0x1414DBEF6ull));
        if (std::wcsstr(lowered.data(), speedhack) != nullptr) return 0;

        static const wchar_t* const dbk64 =
            makima::security::environment::allocate_module_scan_dbk64_token(
                reinterpret_cast<const std::uint16_t*>(0x1414DBF0Cull));
        if (std::wcsstr(lowered.data(), dbk64) != nullptr) return 0;

        static const wchar_t* const dbk32 =
            makima::security::environment::allocate_module_scan_dbk32_token(
                reinterpret_cast<const std::uint16_t*>(0x1414DBF1Aull));
        if (std::wcsstr(lowered.data(), dbk32) != nullptr) return 0;

        static const wchar_t* const api_monitor =
            makima::security::environment::
                allocate_module_scan_api_monitor_token(
                    reinterpret_cast<const std::uint16_t*>(
                        0x1414DBF28ull));
        if (std::wcsstr(lowered.data(), api_monitor) != nullptr) return 0;

        if (std::wcsstr(lowered.data(), http_debugger_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), winapi_override_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), spy_studio_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), echo_mirage_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), fiddler_core_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), titanium_module_token()) != nullptr) {
            return 0;
        }
        if (std::wcsstr(lowered.data(), http_toolkit_module_token()) != nullptr) {
            return 0;
        }
    }
    return 1;
}




std::uint64_t ntdll_probe_exports_are_unhooked() noexcept {
    const std::byte* const image = second_in_load_order_image_base();
    if (image == nullptr) return 1;

    std::int32_t pe_offset{};
    std::memcpy(&pe_offset, image + 0x3c, sizeof(pe_offset));
    std::uint32_t export_directory_rva{};
    std::memcpy(
        &export_directory_rva,
        image + pe_offset + 0x88,
        sizeof(export_directory_rva));
    if (export_directory_rva == 0) return 1;

    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        image + export_directory_rva);
    if (exports->NumberOfNames == 0) return 1;

    const auto* function_rvas = reinterpret_cast<const std::uint32_t*>(
        image + exports->AddressOfFunctions);
    const auto* name_rvas = reinterpret_cast<const std::uint32_t*>(
        image + exports->AddressOfNames);
    const auto* name_ordinals = reinterpret_cast<const std::uint16_t*>(
        image + exports->AddressOfNameOrdinals);

    static const char* const query_information_process =
        makima::security::environment::
            allocate_nt_query_information_process_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DBFF2ull));
    static const char* const set_information_thread =
        makima::security::environment::
            allocate_nt_set_information_thread_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DC00Dull));
    static const char* const close =
        makima::security::environment::allocate_nt_close_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DC025ull));
    static const char* const get_context_thread =
        makima::security::environment::
            allocate_nt_get_context_thread_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DC02Eull));
    static const char* const query_system_information =
        makima::security::environment::
            allocate_nt_query_system_information_export_name(
                reinterpret_cast<const std::uint8_t*>(0x1414DC042ull));
    const std::array<const char*, 5> probes{{
        query_information_process,
        set_information_thread,
        close,
        get_context_thread,
        query_system_information}};
    for (const char* probe : probes) {
        for (std::uint32_t index = 0; index != exports->NumberOfNames; ++index) {
            const char* const export_name = reinterpret_cast<const char*>(
                image + name_rvas[index]);
            if (std::strcmp(export_name, probe) != 0) continue;

            const std::uint16_t ordinal = name_ordinals[index];
            const auto* const address = reinterpret_cast<const unsigned char*>(
                image + function_rvas[ordinal]);
            if (has_jump_prologue(address)) return 0;
            break;
        }
    }
    return 1;
}

}
