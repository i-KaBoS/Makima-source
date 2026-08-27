#include "kernel/symbols/symbols.hpp"

namespace makima::kernel::symbols {




void initialize_pdb_symbol_resolver(
    KernelMapperState& mapper,
    std::uintptr_t loaded_kernel_base) {
    SymbolResolver resolver;

    if (map_ntoskrnl_for_symbol_resolution(
            resolver, loaded_kernel_base, nullptr) == 0) {
        return;
    }

    const auto save_state = resolve_public_symbol(
        resolver, "DbgkpTriageDumpSaveState");
    const auto restore_state = resolve_public_symbol(
        resolver, "DbgkpTriageDumpRestoreState");
    if (restore_state != 0 && save_state != 0) {
        mapper.dbgkp_triage_dump_save_state_rva =
            static_cast<std::uint32_t>(save_state - loaded_kernel_base);
        mapper.dbgkp_triage_dump_restore_state_rva =
            static_cast<std::uint32_t>(restore_state - loaded_kernel_base);
    }
}

}
