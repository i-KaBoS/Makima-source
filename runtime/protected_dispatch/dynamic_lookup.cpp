#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace makima::runtime::raw_dynamic_lookup {
namespace {

constexpr std::uint32_t fnv1a_offset_basis = 0x811C9DC5U;
constexpr std::uint32_t fnv1a_prime = 0x01000193U;

[[nodiscard]] std::uint32_t fnv1a_name_hash(
    const char* text,
    bool fold_ascii_uppercase) noexcept {
    std::uint32_t hash = fnv1a_offset_basis;
    if (text == nullptr) return hash;
    while (*text != '\0') {
        auto value = static_cast<std::uint8_t>(*text++);
        if (fold_ascii_uppercase && value >= 'A' && value <= 'Z') {
            value = static_cast<std::uint8_t>(value + ('a' - 'A'));
        }
        hash = (hash ^ value) * fnv1a_prime;
    }
    return hash;
}

[[nodiscard]] void* find_export_by_hash(
    HMODULE module,
    std::uint32_t export_hash) noexcept {
    const auto* base = reinterpret_cast<const std::byte*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const auto directory =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size == 0) return nullptr;
    const auto* exports = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        base + directory.VirtualAddress);
    const auto* names = reinterpret_cast<const std::uint32_t*>(
        base + exports->AddressOfNames);
    for (std::uint32_t index = 0; index < exports->NumberOfNames; ++index) {
        const auto* name = reinterpret_cast<const char*>(base + names[index]);
        if (fnv1a_name_hash(name, false) == export_hash) {
            return reinterpret_cast<void*>(GetProcAddress(module, name));
        }
    }
    return nullptr;
}

ResolverEnvironment resolver_environment{};

}


ResolverEnvironment* current_environment() noexcept {
    return &resolver_environment;
}



void* resolve_hashed_export(
    ResolverEnvironment* environment,
    std::uint32_t folded_module_hash,
    std::uint32_t export_hash) noexcept {
    (void)environment;
    std::array<HMODULE, 1024> modules{};
    DWORD bytes_needed{};
    if (!EnumProcessModules(
            GetCurrentProcess(),
            modules.data(),
            static_cast<DWORD>(sizeof(modules)),
            &bytes_needed)) {
        return nullptr;
    }
    const auto count = (std::min<std::size_t>)(
        modules.size(), bytes_needed / sizeof(HMODULE));
    std::array<char, MAX_PATH> module_name{};
    for (std::size_t index = 0; index < count; ++index) {
        if (GetModuleBaseNameA(
                GetCurrentProcess(),
                modules[index],
                module_name.data(),
                static_cast<DWORD>(module_name.size())) == 0) {
            continue;
        }
        if (fnv1a_name_hash(module_name.data(), true) == folded_module_hash) {
            return find_export_by_hash(modules[index], export_hash);
        }
    }
    return nullptr;
}


MissingModuleCallback resolve_missing_module_callback(void* dispatch) noexcept {
    return reinterpret_cast<MissingModuleCallback>(dispatch);
}

}
