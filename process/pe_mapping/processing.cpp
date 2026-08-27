#include "process/pe_mapping/memory.hpp"
#include "process/pe_mapping/text_cache.hpp"

namespace makima::process::pe_mapping {


const std::string& kernel_vad_root_field_name() {
    return mapping_text_cache().narrow(
        0x1414E7678ULL,
        makima::process::pe_mapping::literals::kernel_symbol_vad_root);
}

}
