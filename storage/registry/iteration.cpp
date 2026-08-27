#include "storage/registry/registry.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include <windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace makima::storage::registry {

namespace {

constexpr std::uint32_t fnv1a_offset_basis = 0x811C9DC5U;
constexpr std::uint32_t fnv1a_prime = 0x01000193U;

[[nodiscard]] std::uint32_t fnv1a_name_hash(
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







void* resolve_dynamic_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));

    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) {
            callback(module_name);
        }
    }
    return address;
}



void* resolve_ascii_folded_module_and_exact_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}



void* resolve_case_folded_library_and_verbatim_symbol(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_lowercase_module_hash_and_export_hash(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_ascii_normalized_module_and_exact_symbol(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_case_normalized_library_and_verbatim_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_folded_library_hash_and_exact_symbol_hash(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}


void* resolve_lowercased_module_and_unmodified_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(export_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
    return address;
}





std::uintptr_t run_registry_message_loop() noexcept {
    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) != 0) {
        static_cast<void>(TranslateMessage(&message));
        static_cast<void>(DispatchMessageW(&message));
    }
    return static_cast<std::uintptr_t>(message.wParam);
}

std::vector<std::wstring> enumerate_protocol_values(std::wstring_view scheme) {
    std::vector<std::wstring> values;
    if (scheme.empty()) return values;

    const std::wstring path = L"Software\\Classes\\" + std::wstring{scheme};
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_QUERY_VALUE, &key) !=
        ERROR_SUCCESS) {
        return values;
    }

    std::array<wchar_t, 256> name{};
    for (DWORD index = 0;; ++index) {
        DWORD length = static_cast<DWORD>(name.size());
        const LSTATUS status = RegEnumValueW(
            key, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr);
        if (status == ERROR_NO_MORE_ITEMS) break;
        if (status == ERROR_SUCCESS) values.emplace_back(name.data(), length);
    }
    RegCloseKey(key);
    return values;
}

}
