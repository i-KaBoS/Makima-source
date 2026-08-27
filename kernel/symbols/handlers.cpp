#include "kernel/symbols/symbols.hpp"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>
#include <utility>

namespace makima::kernel::symbols {

[[nodiscard]] std::string format_symbol_error(
    std::string_view operation,
    unsigned long error_code) {
    std::string message{operation};
    message += " failed with Win32 error ";
    message += std::to_string(error_code);
    return message;
}

}
