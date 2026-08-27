#include "process/pe_mapping/pe_mapping.hpp"

#include "process/pe_mapping/memory.hpp"
#include "process/pe_mapping/text_cache.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <string>

namespace makima::process::pe_mapping {
namespace decoded = makima::process::pe_mapping::literals;
namespace {

template <
    typename Function,
    typename ModuleProvider,
    typename ExportProvider,
    typename Resolver>
Function cached_export(
    std::uint64_t module_guard,
    ModuleProvider module_provider,
    std::uint64_t export_guard,
    ExportProvider export_provider,
    Resolver resolver) {
    const auto& module = mapping_text_cache().narrow(module_guard, module_provider);
    const auto& name = mapping_text_cache().narrow(export_guard, export_provider);
    return reinterpret_cast<Function>(resolver(module.c_str(), name.c_str()));
}

}


VirtualQueryFunction resolve_virtual_query_api() {
    return cached_export<VirtualQueryFunction>(
        0x1414E7058ULL,
        [] { return allocate_kernel32_library_name_for_snapshot(0x1414D979FLL); },
        0x1414E7048ULL, decoded::virtual_query_api_name,
        resolve_virtual_query_export);
}


CreateToolhelp32SnapshotFunction resolve_create_toolhelp32_snapshot_api() {
    return cached_export<CreateToolhelp32SnapshotFunction>(
        0x1414E7318ULL, decoded::toolhelp_snapshot_kernel32_module_name,
        0x1414E7308ULL, decoded::create_toolhelp32_snapshot_api_name,
        resolve_snapshot_export);
}


Process32FirstWFunction resolve_process32_first_api() {
    return cached_export<Process32FirstWFunction>(
        0x1414E7338ULL, decoded::process_enumeration_kernel32_module_name,
        0x1414E7328ULL,
        [] { return allocate_process32_first_api_name(0x1414D999CLL); },
        resolve_process_first_export);
}


Process32NextWFunction resolve_process32_next_api() {
    return cached_export<Process32NextWFunction>(
        0x1414E7358ULL, decoded::process_next_kernel32_module_name,
        0x1414E7348ULL, decoded::process32_next_w_api_name,
        resolve_process_next_export);
}


LocalFreeFunction resolve_local_free_api() {
    return cached_export<LocalFreeFunction>(
        0x1414E7378ULL, decoded::local_free_kernel32_module_name,
        0x1414E7368ULL, decoded::local_free_api_name,
        resolve_local_free_export);
}

}
