#include "kernel/symbols/symbols.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <ranges>
#include <string_view>
#include <utility>

namespace makima::kernel::symbols {

namespace {

constexpr std::array<char, 32> msf_7_magic{{
    'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+',
    '+', ' ', 'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', '\x1a',
    'D', 'S', '\0', '\0', '\0'}};

[[nodiscard]] std::uint32_t read_u32(
    const std::byte* bytes,
    std::size_t offset) noexcept {
    std::uint32_t value{};
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

void assign_error(MsfDirectoryState& state, std::string_view message) {
    state.error.assign(message);
}

void assign_error(TpiStreamState& state, std::string_view message) {
    state.error.assign(message);
}

}





MsfDirectoryState* initialize_msf_directory_state(
    MsfDirectoryState* output,
    const MsfFileView* file) {




    *output = MsfDirectoryState{};
    output->file = *file;

    if (output->file.size < 0x20) {
        assign_error(*output, "buffer too small");
        return output;
    }
    if (validate_msf_superblock(output) &&
        parse_msf_directory_blocks(output) != 0) {
        output->valid = true;
    }
    return output;
}






bool validate_msf_superblock(MsfDirectoryState* state) {
    const std::byte* const file = state->file.data;
    if (std::memcmp(file, msf_7_magic.data(), msf_7_magic.size()) != 0) {
        assign_error(*state, "bad MSF magic");
        return false;
    }

    state->block_size = read_u32(file, 0x20);
    state->block_count = read_u32(file, 0x28);
    state->directory_bytes = read_u32(file, 0x2c);
    state->directory_block_map = read_u32(file, 0x34);

    if (state->block_size != 0x200 && state->block_size != 0x400 &&
        state->block_size != 0x800 && state->block_size != 0x1000) {
        assign_error(*state, "unsupported block size");
        return false;
    }

    const std::uint64_t declared_file_bytes =
        static_cast<std::uint64_t>(state->block_size) * state->block_count;
    if (declared_file_bytes != state->file.size) {
        static char* const message =
            allocate_msf_size_block_count_mismatch_message(
                msf_size_block_count_mismatch_protected_source.data());
        state->error.assign(message);
        return false;
    }
    if (state->directory_block_map >= state->block_count) {
        assign_error(*state, "blockMapAddr OOB");
        return false;
    }
    return true;
}





std::uint64_t parse_msf_directory_blocks(MsfDirectoryState* state) {
    state->stream_sizes.clear();
    state->stream_blocks.clear();
    state->error.clear();

    const std::uint64_t directory_block_count =
        static_cast<std::uint32_t>(
            state->directory_bytes + state->block_size - 1U) /
        state->block_size;
    const std::uint64_t directory_list_bytes =
        directory_block_count * sizeof(std::uint32_t);
    if (directory_list_bytes > state->block_size) {
        assign_error(*state, "directory block list too large");
        return 0;
    }

    const std::uint64_t list_offset =
        static_cast<std::uint64_t>(state->directory_block_map) *
        state->block_size;
    if (list_offset > state->file.size ||
        directory_list_bytes > state->file.size - list_offset) {
        assign_error(*state, "dir block OOB");
        return 0;
    }

    std::vector<std::byte> directory(state->directory_bytes);
    std::size_t destination = 0;
    for (std::uint64_t index = 0; index < directory_block_count; ++index) {
        const std::uint32_t block = read_u32(
            state->file.data + list_offset,
            static_cast<std::size_t>(index * sizeof(std::uint32_t)));
        if (block >= state->block_count) {
            assign_error(*state, "dir block OOB");
            return 0;
        }

        const std::uint64_t source =
            static_cast<std::uint64_t>(block) * state->block_size;
        const std::size_t copy_bytes = std::min<std::size_t>(
            state->block_size,
            directory.size() - destination);
        if (source > state->file.size ||
            copy_bytes > state->file.size - source) {
            assign_error(*state, "dir block OOB");
            return 0;
        }
        std::memcpy(
            directory.data() + destination,
            state->file.data + source,
            copy_bytes);
        destination += copy_bytes;
    }

    if (directory.size() < sizeof(std::uint32_t)) {
        assign_error(*state, "directory truncated");
        return 0;
    }

    const std::uint32_t stream_count = read_u32(directory.data(), 0);
    constexpr std::uint32_t maximum_streams = 0x100000;
    if (stream_count > maximum_streams) {
        assign_error(*state, "absurd stream count");
        return 0;
    }

    const std::uint64_t size_table_bytes =
        sizeof(std::uint32_t) +
        static_cast<std::uint64_t>(stream_count) * sizeof(std::uint32_t);
    if (size_table_bytes > directory.size()) {
        assign_error(*state, "directory truncated (sizes)");
        return 0;
    }

    state->stream_sizes.resize(stream_count);
    state->stream_blocks.resize(stream_count);
    for (std::uint32_t stream = 0; stream < stream_count; ++stream) {
        state->stream_sizes[stream] = read_u32(
            directory.data(),
            sizeof(std::uint32_t) +
                static_cast<std::size_t>(stream) * sizeof(std::uint32_t));
    }

    std::uint64_t cursor = size_table_bytes;
    for (std::uint32_t stream = 0; stream < stream_count; ++stream) {
        const std::uint32_t stream_size = state->stream_sizes[stream];
        if (stream_size == std::numeric_limits<std::uint32_t>::max()) {
            continue;
        }

        const std::uint64_t stream_block_count =
            static_cast<std::uint32_t>(
                stream_size + state->block_size - 1U) /
            state->block_size;
        const std::uint64_t stream_block_bytes =
            stream_block_count * sizeof(std::uint32_t);
        if (cursor > directory.size() ||
            stream_block_bytes > directory.size() - cursor) {
            assign_error(*state, "directory truncated (blocks)");
            return 0;
        }

        auto& blocks = state->stream_blocks[stream];
        blocks.resize(static_cast<std::size_t>(stream_block_count));
        for (std::uint64_t block_index = 0;
             block_index < stream_block_count;
             ++block_index) {
            const std::uint32_t block = read_u32(
                directory.data(),
                static_cast<std::size_t>(
                    cursor + block_index * sizeof(std::uint32_t)));
            if (block >= state->block_count) {
                assign_error(*state, "stream block OOB");
                return 0;
            }
            blocks[static_cast<std::size_t>(block_index)] = block;
        }
        cursor += stream_block_bytes;
    }

    return 1;
}




bool validate_tpi_stream_header(TpiStreamState* state) {
    const auto stream_bytes = static_cast<std::uint64_t>(
        state->end - state->begin);
    if (stream_bytes < 0x38) {
        assign_error(*state, "TPI header too small");
        return false;
    }

    state->header_size = read_u32(state->begin, 0x04);
    state->type_index_begin = read_u32(state->begin, 0x08);
    state->type_index_end = read_u32(state->begin, 0x0c);
    state->type_record_bytes = read_u32(state->begin, 0x10);

    if (state->header_size < 0x38 || stream_bytes < state->header_size) {
        assign_error(*state, "bad TPI HeaderSize");
        return false;
    }
    if (state->type_record_bytes > stream_bytes - state->header_size) {
        assign_error(*state, "TPI records overflow");
        return false;
    }
    if (state->type_index_begin > state->type_index_end) {
        assign_error(*state, "TPI index range invalid");
        return false;
    }
    return true;
}

}
