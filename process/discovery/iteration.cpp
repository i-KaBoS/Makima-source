#include "process/discovery/discovery.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>
#include <utility>

namespace makima::process::discovery {

namespace {
DiscoveryWorkerRuntime worker_runtime{};

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






void* resolve_process_discovery_export(
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





void* resolve_ascii_folded_discovery_module_export(
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

DiscoveryWorkerRuntime& discovery_worker_runtime() noexcept {
    return worker_runtime;
}




void publish_discovery_worker_notification(
    DiscoveryWorkerCallback callback,
    std::uintptr_t context) noexcept {
    worker_runtime.pending_callback = callback;
    worker_runtime.pending_context = context;
    if (worker_runtime.wake_event != nullptr) {
        static_cast<void>(SetEvent(
            static_cast<HANDLE>(worker_runtime.wake_event)));
    }
}





std::uint32_t discovery_notification_worker(void* argument) noexcept {
    (void)argument;
    while (worker_runtime.running) {
        static_cast<void>(WaitForSingleObject(
            static_cast<HANDLE>(worker_runtime.wake_event), INFINITE));
        if (!worker_runtime.running) {
            break;
        }
        if (worker_runtime.pending_callback != nullptr) {
            worker_runtime.dispatching = true;
            worker_runtime.pending_callback(worker_runtime.pending_context);
            worker_runtime.pending_callback = nullptr;
            worker_runtime.pending_context = 0;
            worker_runtime.dispatching = false;
        }
    }
    return 0;
}

}
