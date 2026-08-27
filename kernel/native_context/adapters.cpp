#include "kernel/native_context/native_context.hpp"

#include <cstdint>
#include <cstring>
#include <new>

#if defined(_MSC_VER)
extern "C" void __cdecl _Init_thread_abort(int*) noexcept;
#endif

namespace makima::kernel::native_context {
namespace {

int symbol_resolver_initialization_epoch{};
int object_reference_initialization_epoch{};
int impersonation_initialization_epoch{};
int token_initialization_epoch{};
int symbol_cache_initialization_epoch{};
int kernel_image_initialization_epoch{};
int native_api_initialization_epoch{};
int context_buffer_initialization_epoch{};
int thread_state_initialization_epoch{};
int attached_object_initialization_epoch{};
int activation_initialization_epoch{};
int diagnostics_initialization_epoch{};

constexpr std::uint64_t cookie_increment = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t cookie_first_multiplier = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t cookie_second_multiplier = 0x94D049BB133111EBULL;

template <std::size_t Extent>
[[nodiscard]] wchar_t* allocate_wide_literal(
    const wchar_t (&literal)[Extent]) {
    static_assert(sizeof(wchar_t) == sizeof(std::uint16_t));
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}

void abort_initialization(int& initialization_epoch) noexcept {
#if defined(_MSC_VER)
    _Init_thread_abort(&initialization_epoch);
#else


    initialization_epoch = 0;
#endif
}

}


void abort_symbol_resolver_initialization() noexcept {
    abort_initialization(symbol_resolver_initialization_epoch);
}


void abort_object_reference_initialization() noexcept {
    abort_initialization(object_reference_initialization_epoch);
}


void abort_impersonation_initialization() noexcept {
    abort_initialization(impersonation_initialization_epoch);
}


void abort_token_initialization() noexcept {
    abort_initialization(token_initialization_epoch);
}


void abort_symbol_cache_initialization() noexcept {
    abort_initialization(symbol_cache_initialization_epoch);
}


void abort_kernel_image_initialization() noexcept {
    abort_initialization(kernel_image_initialization_epoch);
}


void abort_native_api_initialization() noexcept {
    abort_initialization(native_api_initialization_epoch);
}


void abort_context_buffer_initialization() noexcept {
    abort_initialization(context_buffer_initialization_epoch);
}


void abort_thread_state_initialization() noexcept {
    abort_initialization(thread_state_initialization_epoch);
}


void abort_attached_object_initialization() noexcept {
    abort_initialization(attached_object_initialization_epoch);
}


void abort_activation_initialization() noexcept {
    abort_initialization(activation_initialization_epoch);
}


void abort_diagnostics_initialization() noexcept {
    abort_initialization(diagnostics_initialization_epoch);
}



std::uint64_t map_protected_selector(std::uint32_t selector) noexcept {
    return selector >= 0xFFFFFFF3U
        ? static_cast<std::uint32_t>(13U - selector)
        : 27U;
}


std::uint64_t advance_context_cookie(std::uint64_t cookie) noexcept {
    cookie += cookie_increment;
    cookie = (cookie ^ (cookie >> 30)) * cookie_first_multiplier;
    cookie = (cookie ^ (cookie >> 27)) * cookie_second_multiplier;
    return cookie ^ (cookie >> 31);
}


bool context_is_ready(const KernelExecutionContext& context) noexcept {
    return context.phase == ContextPhase::active && context.process_handle != nullptr &&
           context.process_id != 0 && context.kernel_base != 0 &&
           context.attached_object != 0 && !context.exports.empty();
}




wchar_t* allocate_ksecdd_driver_relative_path(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"drivers\\ksecdd.sys");
}

}
