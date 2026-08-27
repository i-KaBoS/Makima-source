#include "payload/auth_mapping/auth_mapping.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include <cstddef>
#include <cstdint>

namespace makima::payload::auth_mapping {
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



void* resolve_ascii_folded_mapping_module_and_exact_export(
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



void* resolve_case_folded_mapping_library_and_verbatim_symbol(
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



void* resolve_lowercase_mapping_module_hash_and_export_hash(
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



void* resolve_normalized_mapping_library_and_exact_symbol(
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

bool has_valid_pe_layout(std::span<const std::byte> bytes) noexcept {
    constexpr std::size_t dos_lfanew = 0x3c;
    if (bytes.size() < dos_lfanew + sizeof(std::uint32_t)) return false;
    if (bytes[0] != std::byte{0x4d} || bytes[1] != std::byte{0x5a}) return false;

    std::uint32_t nt_offset = 0;
    for (std::size_t index = 0; index < sizeof(nt_offset); ++index) {
        nt_offset |= std::to_integer<std::uint32_t>(bytes[dos_lfanew + index]) << (index * 8U);
    }
    if (nt_offset > bytes.size() || bytes.size() - nt_offset < 4U) return false;
    return bytes[nt_offset] == std::byte{0x50} && bytes[nt_offset + 1U] == std::byte{0x45} &&
        bytes[nt_offset + 2U] == std::byte{0} && bytes[nt_offset + 3U] == std::byte{0};
}

}
