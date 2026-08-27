#include "kernel/symbols/symbols.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <new>
#include <optional>
#include <stdexcept>
#include <string_view>

#include <windows.h>

namespace makima::kernel::symbols {
namespace {

[[nodiscard]] bool assign_rsds_identity(
    std::span<const std::byte> record,
    CodeViewIdentity& identity) {
    if (record.size() < 25 || std::memcmp(record.data(), "RSDS", 4) != 0) {
        return false;
    }

    CodeViewIdentity decoded;
    std::copy_n(record.begin() + 4, decoded.guid.size(), decoded.guid.begin());
    std::memcpy(&decoded.age, record.data() + 20, sizeof(decoded.age));
    const auto* name_begin = reinterpret_cast<const char*>(record.data() + 24);
    const auto* name_end = reinterpret_cast<const char*>(record.data() + record.size());
    const auto* terminator = std::find(name_begin, name_end, '\0');
    if (terminator == name_end || terminator == name_begin) return false;

    decoded.pdb_name.assign(name_begin, terminator);
    const auto separator = decoded.pdb_name.find_last_of("/\\");
    if (separator != std::string::npos) {
        decoded.pdb_name.erase(0, separator + 1);
    }
    if (decoded.pdb_name.empty()) return false;
    identity = std::move(decoded);
    return true;
}

[[nodiscard]] bool checked_image_range(
    std::uint32_t image_size,
    std::uint32_t rva,
    std::size_t bytes) noexcept {
    return rva <= image_size && bytes <= image_size - rva;
}

template <std::size_t Extent>
[[nodiscard]] char* allocate_narrow_literal(const char (&literal)[Extent]) {
    auto* output = static_cast<char*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}



[[nodiscard]] const char* not_mz_error_message() {
    static char* const message = allocate_narrow_literal("not MZ");
    return message;
}

[[nodiscard]] const char* bad_e_lfanew_error_message() {
    static char* const message = allocate_narrow_literal("bad e_lfanew");
    return message;
}

[[nodiscard]] const char* not_pe_error_message() {
    static char* const message = allocate_narrow_literal("not PE");
    return message;
}



[[nodiscard]] const char* failed_to_read_debug_directory_error_message() {
    static char* const message =
        allocate_narrow_literal("failed to read debug directory");
    return message;
}

[[nodiscard]] const char* no_rsds_codeview_entry_found_error_message() {
    static char* const message =
        allocate_narrow_literal("no RSDS CodeView entry found");
    return message;
}

[[nodiscard]] std::byte* allocate_tpi_stream_storage(std::size_t size) {
    constexpr std::size_t large_allocation_threshold = 0x1000;
    constexpr std::size_t alignment = 0x20;
    constexpr std::size_t alignment_overhead = alignment + sizeof(void*) - 1;
    if (size < large_allocation_threshold) {
        return static_cast<std::byte*>(::operator new(size));
    }
    if (size > std::numeric_limits<std::size_t>::max() - alignment_overhead) {
        throw std::bad_array_new_length{};
    }
    auto* allocation = static_cast<std::byte*>(
        ::operator new(size + alignment_overhead));
    const auto aligned_address =
        (reinterpret_cast<std::uintptr_t>(allocation) + alignment_overhead) &
        ~(static_cast<std::uintptr_t>(alignment) - 1U);
    auto* aligned = reinterpret_cast<std::byte*>(aligned_address);
    std::memcpy(aligned - sizeof(void*), &allocation, sizeof(allocation));
    return aligned;
}

void release_tpi_stream_storage(
    std::byte* begin,
    std::byte* capacity) noexcept {
    if (begin == nullptr) return;
    const auto size = static_cast<std::size_t>(capacity - begin);
    if (size < 0x1000) {
        ::operator delete(begin);
        return;
    }
    void* allocation{};
    std::memcpy(&allocation, begin - sizeof(allocation), sizeof(allocation));
    ::operator delete(allocation);
}

[[nodiscard]] std::uint16_t read_tpi_u16(
    const std::byte* bytes,
    std::size_t offset) noexcept {
    std::uint16_t value{};
    std::memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

[[nodiscard]] std::optional<std::size_t> numeric_leaf_bytes(
    std::uint16_t leaf) noexcept {
    if (leaf < 0x8000U) return 2U;
    switch (leaf) {
    case 0x8000U:
        return 3U;
    case 0x8001U:
    case 0x8002U:
        return 4U;
    case 0x8003U:
    case 0x8004U:
        return 6U;
    case 0x8009U:
    case 0x800AU:
        return 10U;
    default:
        return std::nullopt;
    }
}

[[nodiscard]] bool is_named_aggregate_leaf(std::uint16_t leaf) noexcept {
    constexpr std::uint16_t lf_class = 0x1504;
    constexpr std::uint16_t lf_structure = 0x1505;
    constexpr std::uint16_t lf_union = 0x1506;
    constexpr std::uint16_t lf_interface = 0x1519;
    return leaf == lf_class || leaf == lf_structure ||
           leaf == lf_union || leaf == lf_interface;
}

}

using SymbolRecordWords = std::array<std::uint64_t, 3>;

TpiStreamState::~TpiStreamState() {
    release_tpi_stream_storage(begin, capacity);
    begin = nullptr;
    end = nullptr;
    capacity = nullptr;
}





TpiStreamState* initialize_tpi_stream_state(
    TpiStreamState* output,
    const MsfDirectoryState* directory) {
    std::construct_at(output);
    output->begin = nullptr;
    output->end = nullptr;
    output->capacity = nullptr;
    output->header_size = 0;
    output->type_index_begin = 0;
    output->type_index_end = 0;
    output->type_record_bytes = 0;
    std::uint32_t parser_seed{};
    std::uint8_t construction_flag;
    (void)initialize_tpi_parser_subobject(
        &output->named_type_indices,
        &parser_seed,
        &construction_flag);
    output->records_ready = false;
    output->ready_padding.fill(std::byte{});

    if (directory->valid && directory->stream_sizes.size() >= 3) {
        const std::uint32_t stream_size = directory->stream_sizes[2];
        if (stream_size != 0 &&
            stream_size != std::numeric_limits<std::uint32_t>::max()) {
            auto* stream = allocate_tpi_stream_storage(stream_size);
            std::memset(stream, 0, stream_size);

            std::size_t output_offset = 0;
            for (const std::uint32_t block : directory->stream_blocks[2]) {
                if (output_offset >= stream_size) break;
                const std::size_t bytes = std::min<std::size_t>(
                    directory->block_size, stream_size - output_offset);
                std::memcpy(
                    stream + output_offset,
                    directory->file.data +
                        static_cast<std::size_t>(block) * directory->block_size,
                    bytes);
                output_offset += bytes;
            }

            output->begin = stream;
            output->end = stream + stream_size;
            output->capacity = output->end;
        }
    }

    if (output->begin == output->end) {
        output->error = "stream 2 empty";
    } else if (validate_tpi_stream_header(output) &&
               (parse_tpi_records(output) & 0xffU) != 0) {
        output->records_ready = true;
    }
    return output;
}




std::unordered_map<std::string, std::uint32_t>*
initialize_tpi_parser_subobject(
    std::unordered_map<std::string, std::uint32_t>* parser_subobject,
    std::uint32_t* seed,
    std::uint8_t* construction_flag) {
    (void)seed;
    (void)construction_flag;
    parser_subobject->clear();
    parser_subobject->max_load_factor(1.0F);
    parser_subobject->rehash(8);
    return parser_subobject;
}




std::uint64_t parse_tpi_records(TpiStreamState* state) {
    constexpr std::uint16_t lf_union = 0x1506;
    constexpr std::uint16_t forward_reference = 0x0080;

    if (state->type_index_end < state->type_index_begin) {
        state->error = "TPI index range invalid";
        return 0;
    }

    const std::size_t type_count =
        static_cast<std::size_t>(state->type_index_end) -
        state->type_index_begin;
    state->record_offsets.assign(type_count, 0U);
    state->named_type_indices.clear();

    const std::size_t stream_bytes = static_cast<std::size_t>(
        state->end - state->begin);
    const std::size_t record_begin = state->header_size;
    const std::size_t record_bytes = state->type_record_bytes;
    if (record_begin > stream_bytes ||
        record_bytes > stream_bytes - record_begin) {
        state->error = "TPI record truncated";
        return 0;
    }
    if (record_bytes <= 3U) return 1;

    const std::size_t record_end = record_begin + record_bytes;
    std::size_t cursor = record_begin;
    std::uint32_t type_index = state->type_index_begin;
    while (cursor < record_end) {
        const std::size_t remaining = record_end - cursor;
        if (remaining < sizeof(std::uint16_t)) {
            state->error = "TPI record truncated";
            return 0;
        }

        const std::uint16_t record_length = read_tpi_u16(state->begin, cursor);
        if (record_length < sizeof(std::uint16_t) ||
            static_cast<std::size_t>(record_length) + 2U > remaining) {
            state->error = "TPI record truncated";
            return 0;
        }

        const std::uint16_t leaf = read_tpi_u16(state->begin, cursor + 2U);
        if (type_index < state->type_index_end) {
            state->record_offsets[
                static_cast<std::size_t>(type_index - state->type_index_begin)] =
                static_cast<std::uint32_t>(cursor);
        }

        const std::size_t payload_bytes = record_length - 2U;
        const std::byte* const payload = state->begin + cursor + 4U;
        if (is_named_aggregate_leaf(leaf)) {
            const std::size_t numeric_offset = leaf == lf_union ? 8U : 16U;
            if (payload_bytes >= numeric_offset + sizeof(std::uint16_t)) {
                const std::uint16_t numeric_leaf =
                    read_tpi_u16(payload, numeric_offset);
                const auto numeric_bytes = numeric_leaf_bytes(numeric_leaf);
                if (numeric_bytes &&
                    numeric_offset + *numeric_bytes < payload_bytes) {
                    const std::size_t name_offset =
                        numeric_offset + *numeric_bytes;
                    const char* const name_begin =
                        reinterpret_cast<const char*>(payload + name_offset);
                    const char* const name_limit =
                        reinterpret_cast<const char*>(payload + payload_bytes);
                    const char* const name_end =
                        std::find(name_begin, name_limit, '\0');
                    if (name_end != name_limit && name_end != name_begin) {
                        std::string name{name_begin, name_end};
                        const std::uint16_t properties =
                            read_tpi_u16(payload, 2U);
                        auto [entry, inserted] =
                            state->named_type_indices.try_emplace(
                                std::move(name), type_index);
                        if (!inserted &&
                            (properties & forward_reference) == 0U) {
                            entry->second = type_index;
                        }
                    }
                }
            }
        }

        cursor += static_cast<std::size_t>(record_length) + 2U;
        ++type_index;
    }
    return 1;
}





[[nodiscard]] SymbolRecordWords* insert_symbol_record(
    std::vector<SymbolRecordWords>& records,
    SymbolRecordWords* position,
    const SymbolRecordWords& value) {
    const std::size_t index = records.empty()
        ? 0U
        : static_cast<std::size_t>(position - records.data());
    if (index > records.size()) throw std::out_of_range{"symbol record iterator"};
    records.insert(records.begin() + static_cast<std::ptrdiff_t>(index), value);
    return records.data() + index;
}

bool KernelImageSnapshot::read(
    std::uintptr_t address,
    std::span<std::byte> destination) const noexcept {
    if (address < virtual_base) return false;
    const auto offset = address - virtual_base;
    if (offset > bytes.size() || destination.size() > bytes.size() - offset) {
        return false;
    }
    std::memcpy(destination.data(), bytes.data() + offset, destination.size());
    return true;
}



bool read_codeview_from_loaded_module(
    const LoadedImageView& image,
    std::uintptr_t mapped_image_base,
    CodeViewIdentity& identity,
    std::string& error) noexcept {
    if (mapped_image_base == 0 || image.image_begin == 0 ||
        image.image_base != mapped_image_base) {
        error = "mapped image base is zero";
        return false;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped_image_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        error = not_mz_error_message();
        return false;
    }
    if (static_cast<std::uint32_t>(dos->e_lfanew) > 0x10000U) {
        error = bad_e_lfanew_error_message();
        return false;
    }
    const auto nt_address = mapped_image_base + static_cast<std::uint32_t>(dos->e_lfanew);
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt_address);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        error = not_pe_error_message();
        return false;
    }
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage < sizeof(IMAGE_DOS_HEADER)) {
        error = "failed to read NT headers";
        return false;
    }

    const auto directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        !checked_image_range(
            nt->OptionalHeader.SizeOfImage,
            directory.VirtualAddress,
            directory.Size)) {
        error = failed_to_read_debug_directory_error_message();
        return false;
    }

    const auto* entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
        mapped_image_base + directory.VirtualAddress);
    const auto count = std::min<std::size_t>(
        directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY), 16U);
    for (std::size_t index = 0; index < count; ++index) {
        const auto& entry = entries[index];
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25 ||
            !checked_image_range(
                nt->OptionalHeader.SizeOfImage,
                entry.AddressOfRawData,
                entry.SizeOfData)) {
            continue;
        }
        const auto* record = reinterpret_cast<const std::byte*>(
            mapped_image_base + entry.AddressOfRawData);
        if (assign_rsds_identity(
                {record, static_cast<std::size_t>(entry.SizeOfData)}, identity)) {
            return true;
        }
    }

    error = no_rsds_codeview_entry_found_error_message();
    return false;
}



bool read_codeview_from_live_kernel(
    KernelModuleState* const* module,
    std::uintptr_t loaded_kernel_base,
    CodeViewIdentity& identity,
    std::string& error) noexcept {
    const KernelImageSnapshot& image = (*module)->image;
    IMAGE_DOS_HEADER dos{};
    if (!image.read(
            loaded_kernel_base,
            std::as_writable_bytes(std::span{&dos, std::size_t{1}}))) {
        error = "failed to read DOS header";
        return false;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        error = not_mz_error_message();
        return false;
    }
    if (static_cast<std::uint32_t>(dos.e_lfanew) > 0x10000U) {
        error = bad_e_lfanew_error_message();
        return false;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!image.read(
            loaded_kernel_base + static_cast<std::uint32_t>(dos.e_lfanew),
            std::as_writable_bytes(std::span{&nt, std::size_t{1}}))) {
        error = "failed to read NT headers";
        return false;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE) {
        error = not_pe_error_message();
        return false;
    }
    if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        error = "failed to read NT headers";
        return false;
    }

    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    if (directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        directory.Size > 0x10000) {
        error.assign(cached_live_kernel_debug_directory_error());
        return false;
    }

    std::vector<IMAGE_DEBUG_DIRECTORY> entries(
        directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY));
    if (entries.empty() || !image.read(
            loaded_kernel_base + directory.VirtualAddress,
            std::as_writable_bytes(std::span{entries}))) {
        error = "CodeView debug directory is unreadable";
        return false;
    }

    for (const auto& entry : entries) {
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25 ||
            entry.SizeOfData > 0x10000) {
            continue;
        }
        std::vector<std::byte> record(entry.SizeOfData);
        if (image.read(
                loaded_kernel_base + entry.AddressOfRawData, record) &&
            assign_rsds_identity(record, identity)) {
            return true;
        }
    }

    error.assign(cached_live_kernel_codeview_error());
    return false;
}



std::uintptr_t resolve_public_symbol(
    const SymbolResolver& resolver,
    std::string_view symbol_name) noexcept {
    if (resolver.public_symbols == nullptr || resolver.loaded_kernel_base == 0) {
        return 0;
    }
    const auto found = resolver.public_symbols->rvas.find(
        std::string{symbol_name});
    return found == resolver.public_symbols->rvas.end()
        ? 0
        : resolver.loaded_kernel_base + found->second;
}

}
