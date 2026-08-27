#include "process/pe_mapping/pe_mapping.hpp"
#include "process/pe_mapping/text_cache.hpp"
#include "process/memory/memory.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace makima::process::pe_mapping {
namespace {

using makima::process::memory::ProcessMemory;

template <typename Structure>
Structure read_structure(const ProcessMemory& memory, VirtualAddress address) {
    Structure value{};
    auto bytes = std::as_writable_bytes(std::span{&value, std::size_t{1}});
    if (memory.read(address, bytes) != bytes.size()) {
        throw MappingError("failed to read remote PE structure");
    }
    return value;
}

template <typename Element>
std::vector<Element> read_array(
    const ProcessMemory& memory,
    VirtualAddress address,
    std::size_t count) {
    std::vector<Element> result(count);
    auto bytes = std::as_writable_bytes(std::span{result});
    if (!bytes.empty() && memory.read(address, bytes) != bytes.size()) {
        throw MappingError("failed to read remote PE table");
    }
    return result;
}

std::string read_remote_string(
    const ProcessMemory& memory,
    VirtualAddress address,
    std::size_t limit = 4096) {
    std::string result;
    result.reserve(std::min<std::size_t>(limit, 128));
    for (std::size_t index = 0; index < limit; ++index) {
        char character{};
        auto byte = std::as_writable_bytes(std::span{&character, std::size_t{1}});
        if (memory.read(address + index, byte) != 1) {
            throw MappingError("failed to read remote export string");
        }
        if (character == '\0') {
            return result;
        }
        result.push_back(character);
    }
    throw MappingError("remote export string is not terminated");
}

struct RemoteExportTable {
    IMAGE_DATA_DIRECTORY directory{};
    IMAGE_EXPORT_DIRECTORY table{};
};

RemoteExportTable read_export_table(
    const ProcessMemory& memory,
    const RemoteModule& module) {
    const auto dos = read_structure<IMAGE_DOS_HEADER>(memory, module.base);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        throw MappingError("remote module has an invalid DOS header");
    }
    const auto nt = read_structure<IMAGE_NT_HEADERS64>(
        memory, module.base + static_cast<std::uint32_t>(dos.e_lfanew));
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        throw MappingError("remote module is not a PE32+ image");
    }
    const auto directory = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        throw MappingError("remote module has no export directory");
    }
    return {
        directory,
        read_structure<IMAGE_EXPORT_DIRECTORY>(
            memory, module.base + directory.VirtualAddress),
    };
}

std::wstring widen_module_name(std::string_view name) {
    std::string narrow{name};
    const HMODULE local = ::LoadLibraryExA(
        narrow.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (local != nullptr) {
        std::array<wchar_t, 32768> path{};
        const DWORD length = ::GetModuleFileNameW(local, path.data(), path.size());
        ::FreeLibrary(local);
        if (length != 0 && length < path.size()) {
            std::wstring result{path.data(), length};
            const auto separator = result.find_last_of(L"\\/");
            return separator == std::wstring::npos ? result : result.substr(separator + 1);
        }
    }
    if (narrow.find('.') == std::string::npos) {
        std::array<char, 0x104> formatted{};
        const auto& filename_format = mapping_text_cache().narrow(
            0x1414E79F8ULL,
            [] { return allocate_dynamic_library_filename_format(0x1414DA01CLL); });
        const int written = std::snprintf(
            formatted.data(), formatted.size(), filename_format.c_str(), narrow.c_str());
        if (written > 0 && static_cast<std::size_t>(written) < formatted.size()) {
            narrow.assign(formatted.data(), static_cast<std::size_t>(written));
        }
    }
    std::wstring result;
    result.reserve(narrow.size());
    for (const unsigned char character : narrow) {
        result.push_back(static_cast<wchar_t>(character));
    }
    return result;
}

VirtualAddress resolve_forwarder(
    std::uint32_t process_id,
    std::string_view forwarder,
    unsigned depth) {
    thread_local unsigned active_forwarders = 0;
    if (depth >= 8 || active_forwarders >= 8) {
        throw MappingError("remote export forwarder chain is too deep");
    }
    struct ForwarderDepthGuard {
        unsigned& value;
        explicit ForwarderDepthGuard(unsigned& depth_value) : value(depth_value) { ++value; }
        ~ForwarderDepthGuard() { --value; }
    } depth_guard{active_forwarders};
    const auto separator = forwarder.rfind('.');
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 == forwarder.size()) {
        throw MappingError("remote export has an invalid forwarder");
    }
    const auto module = find_remote_module(
        process_id, widen_module_name(forwarder.substr(0, separator)));
    if (!module) {
        throw MappingError("forwarded export module is not loaded in target");
    }
    const auto symbol = forwarder.substr(separator + 1);
    if (symbol.front() == '#') {
        const auto ordinal = static_cast<std::uint16_t>(std::stoul(std::string{symbol.substr(1)}));
        return resolve_remote_export_ordinal(process_id, *module, ordinal);
    }
    return resolve_remote_export(process_id, *module, symbol);
}

VirtualAddress export_address_from_index(
    std::uint32_t process_id,
    const ProcessMemory& memory,
    const RemoteModule& module,
    const RemoteExportTable& exports,
    std::uint32_t index,
    unsigned depth) {
    if (index >= exports.table.NumberOfFunctions) {
        throw MappingError("remote export ordinal is outside the function table");
    }
    const auto function_rvas = read_array<std::uint32_t>(
        memory, module.base + exports.table.AddressOfFunctions,
        exports.table.NumberOfFunctions);
    const std::uint32_t rva = function_rvas[index];
    if (rva == 0) {
        return 0;
    }
    const auto export_begin = exports.directory.VirtualAddress;
    const auto export_end = static_cast<std::uint64_t>(export_begin) + exports.directory.Size;
    if (rva >= export_begin && rva < export_end) {
        return resolve_forwarder(
            process_id, read_remote_string(memory, module.base + rva), depth + 1);
    }
    if (rva >= module.image_size) {
        throw MappingError("remote export RVA lies outside the module");
    }
    return module.base + rva;
}

}




VirtualAddress resolve_remote_export(
    std::uint32_t process_id,
    const RemoteModule& module,
    std::string_view symbol_name) {
    if (process_id == 0 || module.base == 0 || symbol_name.empty()) {
        throw MappingError("remote export lookup has an invalid argument");
    }
    HANDLE raw_process = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (raw_process == nullptr) {
        throw MappingError("failed to open target for export lookup");
    }
    struct HandleCloser {
        HANDLE value;
        ~HandleCloser() { ::CloseHandle(value); }
    } closer{raw_process};
    const ProcessMemory memory{raw_process};
    const auto exports = read_export_table(memory, module);
    const auto name_rvas = read_array<std::uint32_t>(
        memory, module.base + exports.table.AddressOfNames, exports.table.NumberOfNames);
    const auto ordinals = read_array<std::uint16_t>(
        memory, module.base + exports.table.AddressOfNameOrdinals, exports.table.NumberOfNames);
    for (std::size_t index = 0; index < name_rvas.size(); ++index) {
        if (read_remote_string(memory, module.base + name_rvas[index]) == symbol_name) {
            return export_address_from_index(
                process_id, memory, module, exports, ordinals[index], 0);
        }
    }
    return 0;
}

VirtualAddress resolve_remote_export_ordinal(
    std::uint32_t process_id,
    const RemoteModule& module,
    std::uint16_t ordinal) {
    HANDLE raw_process = ::OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (raw_process == nullptr) {
        throw MappingError("failed to open target for ordinal lookup");
    }
    struct HandleCloser {
        HANDLE value;
        ~HandleCloser() { ::CloseHandle(value); }
    } closer{raw_process};
    const ProcessMemory memory{raw_process};
    const auto exports = read_export_table(memory, module);
    if (ordinal < exports.table.Base) {
        return 0;
    }
    return export_address_from_index(
        process_id, memory, module, exports, ordinal - exports.table.Base, 0);
}

}
