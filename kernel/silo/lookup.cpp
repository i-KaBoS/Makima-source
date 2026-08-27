#include "kernel/silo/silo.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace makima::kernel::silo {


bool query_silo_information(
    NativeApi& api,
    NativeHandle job,
    std::wstring& text) {
    text.clear();
    if (job == 0 || !api.query_job) {
        return false;
    }
    constexpr std::uint32_t silo_root_directory_information_class = 37;
    const auto information_bytes =
        api.query_job(job, silo_root_directory_information_class);
    if (information_bytes.empty() || (information_bytes.size() & 1U) != 0) {
        return false;
    }
    text = utf16_text_from_little_endian_bytes(information_bytes);
    return !text.empty();
}




std::uint64_t read_object_field(
    std::span<const std::byte> object_bytes,
    std::size_t offset,
    std::size_t width,
    bool sign_extend) {
    if (width == 0 || width > sizeof(std::uint64_t) ||
        offset > object_bytes.size() || width > object_bytes.size() - offset) {
        throw_buffer_bounds_error();
    }

    std::uint64_t field_value = 0;
    for (std::size_t byte_index = 0; byte_index < width; ++byte_index) {
        field_value |= static_cast<std::uint64_t>(
                           std::to_integer<std::uint8_t>(
                               object_bytes[offset + byte_index]))
                       << (byte_index * 8U);
    }
    if (sign_extend && width < sizeof(field_value) &&
        (field_value & (std::uint64_t{1} << (width * 8U - 1U))) != 0) {
        field_value |= ~std::uint64_t{} << (width * 8U);
    }
    return field_value;
}

}
