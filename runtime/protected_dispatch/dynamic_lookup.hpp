#pragma once

#include <cstdint>

namespace makima::runtime::raw_dynamic_lookup {

struct ResolverEnvironment final {
    std::uintptr_t unobserved_00{};
    void* missing_module_dispatch{};
};

using MissingModuleCallback = void (*)(const char* module_name);

[[nodiscard]] ResolverEnvironment* current_environment() noexcept;
[[nodiscard]] void* resolve_hashed_export(
    ResolverEnvironment* environment,
    std::uint32_t folded_module_hash,
    std::uint32_t export_hash) noexcept;
[[nodiscard]] MissingModuleCallback resolve_missing_module_callback(
    void* dispatch) noexcept;

}
