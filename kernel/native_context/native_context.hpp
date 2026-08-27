#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace makima::kernel::native_context {

enum class ContextPhase {
    empty,
    symbols_resolved,
    attached,
    active,
    failed,
};

struct KernelExecutionContext final {
    ContextPhase phase{ContextPhase::empty};
    void* process_handle{};
    std::uint32_t process_id{};
    std::uintptr_t kernel_base{};
    std::uintptr_t attached_object{};
    std::uint32_t expected_identity{};
    std::unordered_map<std::string, std::uintptr_t> exports;
    std::vector<std::string> diagnostics;
};




struct NativeExecutionContextImage final {
    alignas(8) std::array<std::byte, 0x1190> bytes{};
};

static_assert(sizeof(NativeExecutionContextImage) == 0x1190);

void abort_symbol_resolver_initialization() noexcept;
void abort_object_reference_initialization() noexcept;
void abort_impersonation_initialization() noexcept;
void abort_token_initialization() noexcept;
void abort_symbol_cache_initialization() noexcept;
void abort_kernel_image_initialization() noexcept;
void abort_native_api_initialization() noexcept;
void abort_context_buffer_initialization() noexcept;
void abort_thread_state_initialization() noexcept;
void abort_attached_object_initialization() noexcept;
void abort_activation_initialization() noexcept;
void abort_diagnostics_initialization() noexcept;




[[nodiscard]] wchar_t* allocate_se_impersonate_privilege(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_se_debug_privilege(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_schedule_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_se_tcb_privilege(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_se_lock_memory_privilege(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_ntoskrnl_image_name(
    const std::byte* protected_source);
[[nodiscard]] char* allocate_ksecdd_driver_name(
    const std::byte* protected_source);
[[nodiscard]] wchar_t* allocate_ksecdd_driver_relative_path(
    const std::uint16_t* protected_source);

[[nodiscard]] std::uint64_t map_protected_selector(std::uint32_t selector) noexcept;
[[nodiscard]] std::uint64_t advance_context_cookie(std::uint64_t cookie) noexcept;
[[nodiscard]] bool context_is_ready(const KernelExecutionContext& context) noexcept;



[[nodiscard]] bool initialize_kernel_export_view(
    KernelExecutionContext& context,
    void* target_process_handle,
    std::uintptr_t kernel_module_address,
    std::span<const std::string_view> required_export_names);

}
