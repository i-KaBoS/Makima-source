#include "kernel/silo/silo.hpp"

#include <stdexcept>

namespace makima::kernel::silo {


[[noreturn]] void throw_native_api_unavailable() {
    throw std::runtime_error("required native silo API is unavailable");
}


[[noreturn]] void throw_invalid_silo_state() {
    throw std::logic_error("silo context is not initialized for this operation");
}


[[noreturn]] void throw_buffer_bounds_error() {
    throw std::out_of_range("silo buffer offset is outside the owned allocation");
}

}
