#include "storage/services/services.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include "process/pe_mapping/memory.hpp"

#include <windows.h>

#include <winsvc.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace makima::storage::services {

namespace {

constexpr std::uint32_t fnv1a_offset_basis = 0x811C9DC5U;
constexpr std::uint32_t fnv1a_prime = 0x01000193U;

[[nodiscard]] std::uint32_t hash_service_lookup_name(
    const char* text,
    bool fold_ascii_uppercase) noexcept {
    std::uint32_t hash = fnv1a_offset_basis;
    while (*text != '\0') {
        auto value = static_cast<std::uint8_t>(*text++);
        if (fold_ascii_uppercase && value >= 'A' && value <= 'Z') {
            value = static_cast<std::uint8_t>(value + ('a' - 'A'));
        }
        hash = (hash ^ value) * fnv1a_prime;
    }
    return hash;
}

}

std::vector<std::wstring> enumerate_dependent_services(std::wstring_view name) {
    std::vector<std::wstring> names;
    if (name.empty()) return names;
    const std::wstring owned_name{name};
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) return names;
    SC_HANDLE service = OpenServiceW(manager, owned_name.c_str(), SERVICE_ENUMERATE_DEPENDENTS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return names;
    }

    DWORD bytes = 0;
    DWORD count = 0;
    EnumDependentServicesW(service, SERVICE_STATE_ALL, nullptr, 0, &bytes, &count);
    if (GetLastError() == ERROR_MORE_DATA && bytes != 0) {
        std::vector<std::byte> buffer(bytes);
        auto* entries = reinterpret_cast<ENUM_SERVICE_STATUSW*>(buffer.data());
        if (EnumDependentServicesW(
                service, SERVICE_STATE_ALL, entries, bytes, &bytes, &count)) {
            names.reserve(count);
            for (DWORD index = 0; index < count; ++index) {
                if (entries[index].lpServiceName != nullptr) {
                    names.emplace_back(entries[index].lpServiceName);
                }
            }
        }
    }
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return names;
}



void* resolve_case_folded_service_module_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_service_lookup_name(module_name, true),
        hash_service_lookup_name(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_ascii_folded_service_library_symbol(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_service_lookup_name(module_name, true),
        hash_service_lookup_name(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_normalized_service_module_exact_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_service_lookup_name(module_name, true),
        hash_service_lookup_name(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_lowercase_service_library_export_hash(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_service_lookup_name(module_name, true),
        hash_service_lookup_name(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_folded_service_module_verbatim_symbol(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_service_lookup_name(module_name, true),
        hash_service_lookup_name(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}




std::uint64_t resolve_mapped_image_imports(
    char* error_buffer,
    std::int64_t image_base,
    HMODULE(WINAPI* load_library)(LPCSTR),
    FARPROC(WINAPI* get_proc_address)(HMODULE, LPCSTR)) noexcept {
    auto* base = reinterpret_cast<std::byte*>(image_base);
    const auto pe_offset = *reinterpret_cast<const std::int32_t*>(base + 0x3c);
    const auto import_rva = *reinterpret_cast<const std::uint32_t*>(
        base + pe_offset + 0x90);
    const auto import_size = *reinterpret_cast<const std::uint32_t*>(
        base + pe_offset + 0x94);
    if (import_rva == 0 || import_size == 0) return 1;

    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        base + import_rva);
    for (; descriptor->Name != 0; ++descriptor) {
        const char* dll_name = reinterpret_cast<const char*>(
            base + descriptor->Name);
        const HMODULE module = load_library(dll_name);
        if (module == nullptr) {
            static const std::string label =
                process::pe_mapping::literals::import_dll_not_found_message();
            static const std::string format =
                process::pe_mapping::literals::label_detail_format();
            sprintf_s(
                error_buffer,
                0x100,
                format.c_str(),
                label.c_str(),
                dll_name);
            return 0;
        }

        const std::uint32_t lookup_rva = descriptor->OriginalFirstThunk != 0
            ? descriptor->OriginalFirstThunk
            : descriptor->FirstThunk;
        auto* lookup = reinterpret_cast<const std::uint64_t*>(base + lookup_rva);
        auto* iat = reinterpret_cast<std::uint64_t*>(
            base + descriptor->FirstThunk);
        for (; *lookup != 0; ++lookup, ++iat) {
            const std::uint64_t lookup_value = *lookup;
            const LPCSTR import_name = static_cast<std::int64_t>(lookup_value) < 0
                ? reinterpret_cast<LPCSTR>(lookup_value & 0xffff)
                : reinterpret_cast<LPCSTR>(base + lookup_value + 2);
            const FARPROC resolved = get_proc_address(module, import_name);
            *iat = reinterpret_cast<std::uint64_t>(resolved);
            if (resolved == nullptr) {
                static const std::string message =
                    process::pe_mapping::literals::failed_to_resolve_import_message();
                strncpy_s(error_buffer, 0x100, message.c_str(), _TRUNCATE);
                return 0;
            }
        }
    }
    return 1;
}

}
