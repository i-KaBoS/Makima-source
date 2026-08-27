#include "kernel/silo/silo.hpp"

#include <algorithm>
#include <stdexcept>

namespace makima::kernel::silo {


[[noreturn]] void throw_vector_too_long() {
    throw std::length_error("vector too long");
}



void copy_aligned_kernel_text(
    std::span<std::byte, 16> destination,
    std::span<const std::byte, 16> source) noexcept {
    std::copy(source.begin(), source.end(), destination.begin());
}

}
