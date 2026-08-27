#include "kernel/silo/silo.hpp"

#include <stdexcept>

namespace makima::kernel::silo {


[[noreturn]] void throw_invalid_string_view_position() {
    throw std::out_of_range("invalid string_view position");
}

}
