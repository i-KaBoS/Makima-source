#include "kernel/native_context/native_context.hpp"

#include <windows.h>

#include <string>
#include <unordered_map>
#include <utility>

namespace makima::kernel::native_context {


bool initialize_kernel_export_view(
    KernelExecutionContext& context,
    void* target_process_handle,
    std::uintptr_t kernel_module_address,
    std::span<const std::string_view> required_export_names) {
    context = {};
    context.process_handle = target_process_handle;
    context.process_id = target_process_handle == nullptr
        ? 0
        : GetProcessId(static_cast<HANDLE>(target_process_handle));
    context.kernel_base = kernel_module_address;

    if (target_process_handle == nullptr || context.process_id == 0 ||
        kernel_module_address == 0) {
        context.phase = ContextPhase::failed;
        context.diagnostics.emplace_back("process handle or kernel image is unavailable");
        return false;
    }

    std::unordered_map<std::string, std::uintptr_t> resolved_exports;
    resolved_exports.reserve(required_export_names.size());
    for (const auto export_name : required_export_names) {
        if (export_name.empty()) {
            context.phase = ContextPhase::failed;
            context.diagnostics.emplace_back("an empty kernel export was requested");
            return false;
        }
        const std::string symbol_name{export_name};
        const auto exported_procedure = GetProcAddress(
            reinterpret_cast<HMODULE>(kernel_module_address),
            symbol_name.c_str());
        const auto export_address =
            reinterpret_cast<std::uintptr_t>(exported_procedure);
        if (export_address == 0) {
            context.phase = ContextPhase::failed;
            context.diagnostics.emplace_back(
                "required kernel export is missing: " + std::string{export_name});
            return false;
        }
        resolved_exports.insert_or_assign(std::string{export_name}, export_address);
    }

    context.exports = std::move(resolved_exports);
    context.phase = ContextPhase::symbols_resolved;
    return true;
}









}
