#include "storage/registry/registry.hpp"
#include "process/discovery/discovery.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <cstdint>
#include <string>
#include <windows.h>

namespace makima::storage::registry {
namespace {




bool registry_guard_worker_running{};
HANDLE registry_guard_worker{};


RegistryTelemetryWorkerRuntime registry_telemetry_runtime{};

constexpr std::uint32_t fnv1a_offset_basis = 0x811C9DC5U;
constexpr std::uint32_t fnv1a_prime = 0x01000193U;

[[nodiscard]] inline std::uint32_t hash_registry_lookup_name(
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




void stop_registry_guard_worker() noexcept {
    registry_guard_worker_running = false;
    if (registry_guard_worker != nullptr) {
        static_cast<void>(WaitForSingleObject(registry_guard_worker, 5'000U));
        static_cast<void>(CloseHandle(registry_guard_worker));
        registry_guard_worker = nullptr;
    }
}

RegistryTelemetryWorkerRuntime& registry_telemetry_worker_runtime() noexcept {
    return registry_telemetry_runtime;
}





void start_registry_telemetry_worker() noexcept {
    registry_telemetry_runtime.sleep =
        reinterpret_cast<RegistrySleep>(&::Sleep);
    registry_telemetry_runtime.query_counter =
        reinterpret_cast<RegistryQueryCounter>(&::QueryPerformanceCounter);
    registry_telemetry_runtime.running = true;
    registry_telemetry_runtime.worker_thread = ::CreateThread(
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            telemetry::reporting::registry_telemetry_worker),
        nullptr,
        0,
        nullptr);
}




void stop_registry_telemetry_worker() noexcept {
    registry_telemetry_runtime.running = false;
    if (registry_telemetry_runtime.worker_thread != nullptr) {
        static_cast<void>(::WaitForSingleObject(
            static_cast<HANDLE>(registry_telemetry_runtime.worker_thread),
            5'000U));
        static_cast<void>(::CloseHandle(
            static_cast<HANDLE>(registry_telemetry_runtime.worker_thread)));
        registry_telemetry_runtime.worker_thread = nullptr;
    }
}




bool start_process_discovery_notification_worker() noexcept {
    auto& runtime = process::discovery::discovery_worker_runtime();
    runtime.wake_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (runtime.wake_event == nullptr) {
        return false;
    }

    runtime.release_event = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (runtime.release_event == nullptr) {
        return false;
    }

    runtime.worker_thread = CreateThread(
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(
            process::discovery::discovery_notification_worker),
        nullptr,
        0,
        nullptr);
    return runtime.worker_thread != nullptr;
}




void stop_process_discovery_notification_worker() noexcept {
    auto& runtime = process::discovery::discovery_worker_runtime();
    runtime.running = false;
    if (runtime.wake_event != nullptr) {
        static_cast<void>(SetEvent(static_cast<HANDLE>(runtime.wake_event)));
    }
    if (runtime.worker_thread != nullptr) {
        static_cast<void>(WaitForSingleObject(
            static_cast<HANDLE>(runtime.worker_thread), 2'000U));
        static_cast<void>(CloseHandle(
            static_cast<HANDLE>(runtime.worker_thread)));
        runtime.worker_thread = nullptr;
    }
    if (runtime.wake_event != nullptr) {
        static_cast<void>(CloseHandle(static_cast<HANDLE>(runtime.wake_event)));
        runtime.wake_event = nullptr;
    }
    if (runtime.release_event != nullptr) {
        static_cast<void>(CloseHandle(
            static_cast<HANDLE>(runtime.release_event)));
        runtime.release_event = nullptr;
    }
}





std::uint64_t current_process_has_no_debug_port() noexcept {
    using NtQueryInformationProcess = LONG (NTAPI*)(
        HANDLE process,
        ULONG process_information_class,
        void* process_information,
        ULONG process_information_length,
        ULONG* return_length);

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_process_information =
        ntdll == nullptr ? nullptr :
        reinterpret_cast<NtQueryInformationProcess>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query_process_information == nullptr) {
        return 1U;
    }

    std::uintptr_t debug_port = 0;
    const LONG status = query_process_information(
        ::GetCurrentProcess(),
        7U,
        &debug_port,
        sizeof(debug_port),
        nullptr);
    return status != 0 || debug_port == 0 ? 1U : 0U;
}

[[nodiscard]] bool ensure_protocol_handler(
    const ProtocolRegistration& registration,
    bool enabled) noexcept {
    if (!enabled) return remove_protocol_handler(registration.scheme);

    std::wstring current;
    if (read_protocol_command(registration.scheme, current) &&
        current == registration.command) {
        return true;
    }
    return install_protocol_handler(registration);
}





void* resolve_case_folded_module_and_exact_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_registry_lookup_name(module_name, true),
        hash_registry_lookup_name(export_name, false));

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





void* resolve_folded_module_and_verbatim_export(
    const char* module_name,
    const char* export_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        hash_registry_lookup_name(module_name, true),
        hash_registry_lookup_name(export_name, false));

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

}
