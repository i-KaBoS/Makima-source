#include "kernel/symbols/symbols.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <limits>
#include <new>
#include <sstream>
#include <utility>

namespace makima::kernel::symbols {
namespace {

template <typename Value>
[[nodiscard]] bool read_scalar(
    std::span<const std::byte> bytes,
    std::size_t offset,
    Value& output) noexcept {
    if (offset > bytes.size() || sizeof(Value) > bytes.size() - offset) {
        return false;
    }
    std::memcpy(&output, bytes.data() + offset, sizeof(Value));
    return true;
}

[[nodiscard]] bool copy_blocks(
    std::span<const std::byte> file,
    std::uint32_t block_size,
    std::span<const std::uint32_t> block_numbers,
    std::size_t byte_count,
    std::vector<std::byte>& output) {
    output.clear();
    output.reserve(byte_count);
    for (const std::uint32_t block : block_numbers) {
        const auto offset = static_cast<std::uint64_t>(block) * block_size;
        if (offset >= file.size()) {
            return false;
        }
        const auto remaining = byte_count - output.size();
        const auto copied = std::min<std::size_t>(
            {remaining, block_size, file.size() - static_cast<std::size_t>(offset)});
        output.insert(
            output.end(),
            file.begin() + static_cast<std::size_t>(offset),
            file.begin() + static_cast<std::size_t>(offset) + copied);
        if (output.size() == byte_count) {
            return true;
        }
    }
    return output.size() == byte_count;
}

[[nodiscard]] bool parse_stream_directory(
    std::span<const std::byte> pdb,
    PdbStreamDirectory& directory,
    std::string& error) {
    const MsfFileView file{pdb.data(), pdb.size()};
    MsfDirectoryState state;
    initialize_msf_directory_state(&state, &file);
    if (!state.valid) {
        error = state.error;
        return false;
    }

    directory.block_size = state.block_size;
    directory.file = pdb;
    directory.sizes = std::move(state.stream_sizes);
    directory.blocks = std::move(state.stream_blocks);
    return true;
}

[[nodiscard]] bool copy_msf_stream_bytes(
    const PdbStreamDirectory& directory,
    std::size_t index,
    std::vector<std::byte>& output) {
    if (index >= directory.sizes.size() ||
        directory.sizes[index] == std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    return copy_blocks(
        directory.file,
        directory.block_size,
        directory.blocks[index],
        directory.sizes[index],
        output);
}

[[nodiscard]] bool identity_matches(
    const PdbStreamDirectory& directory,
    const CodeViewIdentity& identity,
    std::string& error) {
    std::vector<std::byte> pdb_stream;
    if (!copy_msf_stream_bytes(directory, 1, pdb_stream) || pdb_stream.size() < 28) {
        error = "stream 1 too small for GUID check";
        return false;
    }
    std::uint32_t age{};
    if (!read_scalar(std::span<const std::byte>{pdb_stream}, 8, age) ||
        age != identity.age ||
        !std::equal(
            identity.guid.begin(), identity.guid.end(), pdb_stream.begin() + 12)) {
        error = "PDB GUID mismatch";
        return false;
    }
    return true;
}

[[nodiscard]] bool parse_public_symbols(
    const PdbStreamDirectory& directory,
    std::unordered_map<std::string, std::uint32_t>& symbols,
    std::string& error) {
    std::vector<std::byte> dbi;
    if (!copy_msf_stream_bytes(directory, 3, dbi) || dbi.size() < 64) {
        static const char* const message = allocate_dbi_stream_too_small_message(
            reinterpret_cast<const std::uint8_t*>(0x1414DA6DCull));
        error = message;
        return false;
    }
    std::uint16_t symbol_stream{};
    std::uint32_t module_info_size{};
    std::uint32_t section_contribution_size{};
    std::uint32_t section_map_size{};
    std::uint32_t source_info_size{};
    std::uint32_t type_server_map_size{};
    std::uint32_t optional_debug_size{};
    std::uint32_t ec_size{};
    if (!read_scalar(std::span<const std::byte>{dbi}, 20, symbol_stream) ||
        !read_scalar(std::span<const std::byte>{dbi}, 24, module_info_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 28, section_contribution_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 32, section_map_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 36, source_info_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 40, type_server_map_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 48, optional_debug_size) ||
        !read_scalar(std::span<const std::byte>{dbi}, 52, ec_size) ||
        symbol_stream == 0xffff || symbol_stream >= directory.sizes.size()) {
        error = "DBI sym_record_stream index invalid";
        return false;
    }
    const std::uint64_t debug_offset = 64ULL + module_info_size +
        section_contribution_size + section_map_size + source_info_size +
        type_server_map_size + ec_size;
    if (debug_offset > dbi.size() ||
        optional_debug_size > dbi.size() - debug_offset) {
        error = "OptionalDbgHeader overflows DBI stream";
        return false;
    }
    if (optional_debug_size < 12) {
        error = "OptionalDbgHeader too small for section header entry";
        return false;
    }
    std::uint16_t section_header_stream{};
    if (!read_scalar(
            std::span<const std::byte>{dbi}, debug_offset + 10,
            section_header_stream) ||
        section_header_stream == 0xffff ||
        section_header_stream >= directory.sizes.size()) {
        error = "section header stream index invalid";
        return false;
    }
    std::vector<std::byte> section_bytes;
    if (!copy_msf_stream_bytes(directory, section_header_stream, section_bytes) ||
        section_bytes.size() < sizeof(IMAGE_SECTION_HEADER)) {
        error = "section header stream empty or too small";
        return false;
    }
    const auto section_count = section_bytes.size() / sizeof(IMAGE_SECTION_HEADER);
    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        section_bytes.data());
    std::vector<std::byte> records;
    if (!copy_msf_stream_bytes(directory, symbol_stream, records) || records.empty()) {
        error = "symbol record stream empty";
        return false;
    }
    std::size_t cursor{};
    while (cursor + 4 <= records.size()) {
        std::uint16_t record_length{};
        std::uint16_t kind{};
        read_scalar(std::span<const std::byte>{records}, cursor, record_length);
        read_scalar(std::span<const std::byte>{records}, cursor + 2, kind);
        const std::size_t end = cursor + sizeof(record_length) + record_length;
        if (record_length < 2 || end > records.size()) {
            break;
        }

        if (kind == 0x110e && record_length >= 12) {
            std::uint32_t section_offset{};
            std::uint16_t section{};
            read_scalar(
                std::span<const std::byte>{records}, cursor + 8,
                section_offset);
            read_scalar(
                std::span<const std::byte>{records}, cursor + 12,
                section);
            if (section != 0 && section <= section_count) {
                const std::size_t name_offset = cursor + 14;
                const auto* name_begin = reinterpret_cast<const char*>(
                    records.data() + name_offset);
                const auto* name_end = reinterpret_cast<const char*>(
                    records.data() + end);
                const auto* terminator = std::find(name_begin, name_end, '\0');
                if (terminator != name_begin) {
                    symbols.emplace(
                        std::string{name_begin, terminator},
                        sections[section - 1].VirtualAddress + section_offset);
                }
            }
        }
        cursor = (end + 3) & ~std::size_t{3};
    }
    if (symbols.empty()) {
        error = "no symbols found in symbol record stream";
        return false;
    }
    return true;
}

[[nodiscard]] std::string symbol_key(const CodeViewIdentity& identity) {
    const auto byte = [&](std::size_t index) {
        return std::to_integer<unsigned>(identity.guid[index]);
    };
    std::ostringstream key;
    key << std::uppercase << std::hex << std::setfill('0')
        << std::setw(2) << byte(3) << std::setw(2) << byte(2)
        << std::setw(2) << byte(1) << std::setw(2) << byte(0)
        << std::setw(2) << byte(5) << std::setw(2) << byte(4)
        << std::setw(2) << byte(7) << std::setw(2) << byte(6);
    for (std::size_t index = 8; index < identity.guid.size(); ++index) {
        key << std::setw(2) << byte(index);
    }
    key << identity.age;
    return key.str();
}

[[nodiscard]] std::wstring widen_ascii(std::string_view value) {
    return {value.begin(), value.end()};
}

}




std::uint64_t download_and_parse_matching_pdb(
    SymbolResolver& resolver,
    const CodeViewIdentity& identity) {
    const std::string key = symbol_key(identity);
    const std::string request = "/download/symbols/" + identity.pdb_name +
        "/" + key + "/" + identity.pdb_name;
    const std::wstring wide_request = widen_ascii(request);




    std::vector<std::byte> incoming_database;
    if (!load_encrypted_symbol_cache(
            key, identity.pdb_name, incoming_database)) {
        if (!microsoft_symbol_server_download(
                wide_request, incoming_database, resolver.error)) {
            resolver.error.insert(0, "PDB download failed: ");
            return false;
        }
        (void)save_encrypted_symbol_cache(
            key, identity.pdb_name, incoming_database);
    }






    auto parsed_database = std::make_unique<ParsedPdbState>();
    const bool directory_valid = parse_stream_directory(
        incoming_database,
        parsed_database->directory,
        resolver.error);
    parsed_database->directory_valid = directory_valid;
    resolver.parsed_database = std::move(parsed_database);
    resolver.program_database = std::move(incoming_database);

    if (!directory_valid) {
        resolver.error.insert(0, "MSF parse failed: ");
        return false;
    }
    if (!identity_matches(
            resolver.parsed_database->directory, identity, resolver.error)) {
        return false;
    }





    MsfDirectoryState tpi_directory{};
    tpi_directory.file = {
        resolver.parsed_database->directory.file.data(),
        resolver.parsed_database->directory.file.size()};
    tpi_directory.valid = true;
    tpi_directory.block_size = resolver.parsed_database->directory.block_size;
    tpi_directory.stream_sizes = resolver.parsed_database->directory.sizes;
    tpi_directory.stream_blocks = resolver.parsed_database->directory.blocks;

    void* const tpi_storage = ::operator new(sizeof(TpiStreamState));
    try {
        resolver.parsed_database->type_information.reset(
            initialize_tpi_stream_state(
                static_cast<TpiStreamState*>(tpi_storage), &tpi_directory));
    } catch (...) {
        ::operator delete(tpi_storage);
        throw;
    }

    auto public_symbols = std::make_unique<PublicSymbolState>();
    if (!parse_public_symbols(
            resolver.parsed_database->directory,
            public_symbols->rvas,
            resolver.error)) {
        resolver.error.insert(0, "DBI/symbol parse failed: ");
        return false;
    }

    resolver.public_symbols = std::move(public_symbols);
    resolver.parsed_database->public_symbols_ready = true;
    return true;
}

}
