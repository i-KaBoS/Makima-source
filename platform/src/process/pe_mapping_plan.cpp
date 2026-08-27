#include "makima/platform/pe_mapping_plan.hpp"
#include "process/pe_mapping/pe_mapping.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <sstream>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace makima::platform {
namespace {

using application::ApplicationError;

template <typename Integer>
bool checked_add(Integer left, Integer right, Integer& output) noexcept {
    if (right > std::numeric_limits<Integer>::max() - left) {
        return false;
    }
    output = static_cast<Integer>(left + right);
    return true;
}

class ImageReader final {
public:
    ImageReader(std::span<const std::uint8_t> image, const IMAGE_OPTIONAL_HEADER64& optional_header)
        : image_(image), optional_header_(optional_header) {}

    void set_sections(std::vector<IMAGE_SECTION_HEADER> sections) {
        sections_ = std::move(sections);
    }

    template <typename T>
    [[nodiscard]] T file_structure(std::size_t offset) const {
        if (offset > image_.size() || sizeof(T) > image_.size() - offset) {
            throw ApplicationError("portable executable structure is truncated");
        }
        T result{};
        std::memcpy(&result, image_.data() + offset, sizeof(result));
        return result;
    }

    [[nodiscard]] std::span<const std::uint8_t> rva_bytes(
        std::uint32_t rva,
        std::size_t size) const {
        if (size == 0) {
            return {};
        }
        std::size_t file_offset = 0;
        if (rva < optional_header_.SizeOfHeaders) {
            file_offset = rva;
        } else {
            const auto section = std::find_if(
                sections_.begin(),
                sections_.end(),
                [rva](const IMAGE_SECTION_HEADER& candidate) {
                    return rva >= candidate.VirtualAddress &&
                           static_cast<std::uint64_t>(rva - candidate.VirtualAddress) <
                               candidate.SizeOfRawData;
                });
            if (section == sections_.end()) {
                throw ApplicationError("RVA does not refer to file-backed image data");
            }
            file_offset = static_cast<std::size_t>(section->PointerToRawData) +
                          (rva - section->VirtualAddress);
        }
        if (file_offset > image_.size() || size > image_.size() - file_offset) {
            throw ApplicationError("RVA range extends beyond the portable executable file");
        }
        return image_.subspan(file_offset, size);
    }

    template <typename T>
    [[nodiscard]] T rva_structure(std::uint32_t rva) const {
        const auto bytes = rva_bytes(rva, sizeof(T));
        T result{};
        std::memcpy(&result, bytes.data(), sizeof(result));
        return result;
    }

    [[nodiscard]] std::string rva_string(std::uint32_t rva, std::size_t limit = 4096) const {
        std::string result;
        result.reserve(std::min<std::size_t>(limit, 128));
        for (std::size_t index = 0; index < limit; ++index) {
            std::uint32_t current = 0;
            if (!checked_add(rva, static_cast<std::uint32_t>(index), current)) {
                throw ApplicationError("portable executable string RVA overflowed");
            }
            const char character = static_cast<char>(rva_bytes(current, 1)[0]);
            if (character == '\0') {
                if (result.empty()) {
                    throw ApplicationError("portable executable contains an empty required string");
                }
                return result;
            }
            if (static_cast<unsigned char>(character) < 0x20 ||
                static_cast<unsigned char>(character) > 0x7e) {
                throw ApplicationError("portable executable contains a non-ASCII import string");
            }
            result.push_back(character);
        }
        throw ApplicationError("portable executable string is not terminated within its limit");
    }

private:
    std::span<const std::uint8_t> image_;
    IMAGE_OPTIONAL_HEADER64 optional_header_{};
    std::vector<IMAGE_SECTION_HEADER> sections_;
};

SectionAccess section_access(DWORD characteristics) noexcept {
    auto result = SectionAccess::none;
    if ((characteristics & IMAGE_SCN_MEM_READ) != 0) {
        result = result | SectionAccess::read;
    }
    if ((characteristics & IMAGE_SCN_MEM_WRITE) != 0) {
        result = result | SectionAccess::write;
    }
    if ((characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
        result = result | SectionAccess::execute;
    }
    return result;
}

std::string section_name(const IMAGE_SECTION_HEADER& section) {
    const auto* begin = reinterpret_cast<const char*>(section.Name);
    const auto* end = std::find(begin, begin + IMAGE_SIZEOF_SHORT_NAME, '\0');
    return std::string(begin, end);
}

void validate_sections(
    std::span<const std::uint8_t> image,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    std::span<const IMAGE_SECTION_HEADER> sections) {
    struct Range {
        std::uint64_t begin{};
        std::uint64_t end{};
    };
    std::vector<Range> virtual_ranges;
    std::vector<Range> raw_ranges;
    for (const auto& section : sections) {
        const auto virtual_size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        const auto virtual_end = static_cast<std::uint64_t>(section.VirtualAddress) + virtual_size;
        if (virtual_end > optional_header.SizeOfImage) {
            throw ApplicationError("section virtual range exceeds SizeOfImage");
        }
        if (virtual_size != 0) {
            virtual_ranges.push_back({section.VirtualAddress, virtual_end});
        }
        const auto raw_end = static_cast<std::uint64_t>(section.PointerToRawData) + section.SizeOfRawData;
        if (raw_end > image.size()) {
            throw ApplicationError("section raw range exceeds the portable executable file");
        }
        if (section.SizeOfRawData != 0) {
            raw_ranges.push_back({section.PointerToRawData, raw_end});
        }
    }
    const auto reject_overlap = [](std::vector<Range>& ranges, const char* message) {
        std::ranges::sort(ranges, {}, &Range::begin);
        for (std::size_t index = 1; index < ranges.size(); ++index) {
            if (ranges[index].begin < ranges[index - 1].end) {
                throw ApplicationError(message);
            }
        }
    };
    reject_overlap(virtual_ranges, "portable executable sections overlap in virtual memory");
    reject_overlap(raw_ranges, "portable executable sections overlap in the file");
}

bool directory_present(const IMAGE_DATA_DIRECTORY& directory) {
    if ((directory.VirtualAddress == 0) != (directory.Size == 0)) {
        throw ApplicationError("portable executable data directory is only partially specified");
    }
    return directory.VirtualAddress != 0;
}

void parse_relocations(
    const ImageReader& reader,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    const IMAGE_DATA_DIRECTORY& directory,
    PortableExecutableMappingPlan& plan) {
    if (!directory_present(directory)) {
        return;
    }
    std::uint32_t consumed = 0;
    while (consumed < directory.Size) {
        if (directory.Size - consumed < sizeof(IMAGE_BASE_RELOCATION)) {
            throw ApplicationError("base relocation directory has a truncated block header");
        }
        const auto block = reader.rva_structure<IMAGE_BASE_RELOCATION>(directory.VirtualAddress + consumed);
        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
            block.SizeOfBlock > directory.Size - consumed ||
            (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(std::uint16_t) != 0) {
            throw ApplicationError("base relocation block has invalid geometry");
        }
        const auto entries =
            (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        for (std::uint32_t index = 0; index < entries; ++index) {
            const auto entry = reader.rva_structure<std::uint16_t>(
                directory.VirtualAddress + consumed + sizeof(IMAGE_BASE_RELOCATION) +
                index * sizeof(std::uint16_t));
            const auto type = static_cast<std::uint16_t>(entry >> 12U);
            const auto offset = static_cast<std::uint16_t>(entry & 0x0fffU);
            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;
            }
            const auto target = static_cast<std::uint64_t>(block.VirtualAddress) + offset;
            if (target >= optional_header.SizeOfImage ||
                (type == IMAGE_REL_BASED_DIR64 && target + sizeof(std::uint64_t) > optional_header.SizeOfImage)) {
                throw ApplicationError("base relocation target lies outside SizeOfImage");
            }
            plan.relocations.push_back({static_cast<std::uint32_t>(target), type});
            if (type != IMAGE_REL_BASED_DIR64) {
                plan.unsupported_execution_steps.push_back(
                    "relocation type " + std::to_string(type) + " is not valid for this AMD64 mapping planner");
            }
        }
        consumed += block.SizeOfBlock;
    }
}

void parse_imports(
    const ImageReader& reader,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    const IMAGE_DATA_DIRECTORY& directory,
    PortableExecutableMappingPlan& plan) {
    if (!directory_present(directory)) {
        return;
    }
    bool terminated = false;
    for (std::size_t module_index = 0;
         (module_index + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR) <= directory.Size;
         ++module_index) {
        const auto descriptor = reader.rva_structure<IMAGE_IMPORT_DESCRIPTOR>(
            directory.VirtualAddress +
            static_cast<std::uint32_t>(module_index * sizeof(IMAGE_IMPORT_DESCRIPTOR)));
        if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 &&
            descriptor.Name == 0) {
            terminated = true;
            break;
        }
        if (descriptor.Name == 0 || descriptor.FirstThunk == 0) {
            throw ApplicationError("import descriptor is missing a module name or address table");
        }
        ImportModulePlan module;
        module.name = reader.rva_string(descriptor.Name, 512);
        const std::uint32_t lookup_table = static_cast<std::uint32_t>(
            descriptor.OriginalFirstThunk != 0
                ? descriptor.OriginalFirstThunk
                : descriptor.FirstThunk);
        bool thunk_terminated = false;
        for (std::size_t symbol_index = 0; symbol_index < 65'536; ++symbol_index) {
            const auto offset = symbol_index * sizeof(std::uint64_t);
            if (offset > std::numeric_limits<std::uint32_t>::max()) {
                throw ApplicationError("import lookup table offset overflowed");
            }
            std::uint32_t lookup_rva = 0;
            std::uint32_t address_rva = 0;
            if (!checked_add(lookup_table, static_cast<std::uint32_t>(offset), lookup_rva) ||
                !checked_add(
                    static_cast<std::uint32_t>(descriptor.FirstThunk),
                    static_cast<std::uint32_t>(offset),
                    address_rva) ||
                static_cast<std::uint64_t>(address_rva) + sizeof(std::uint64_t) >
                    optional_header.SizeOfImage) {
                throw ApplicationError("import thunk table exceeds SizeOfImage");
            }
            const auto thunk = reader.rva_structure<std::uint64_t>(lookup_rva);
            if (thunk == 0) {
                thunk_terminated = true;
                break;
            }
            ImportSymbolPlan symbol;
            symbol.address_table_rva = address_rva;
            if ((thunk & IMAGE_ORDINAL_FLAG64) != 0) {
                symbol.by_ordinal = true;
                symbol.ordinal = static_cast<std::uint16_t>(thunk & 0xffffU);
                if (symbol.ordinal == 0) {
                    throw ApplicationError("ordinal import uses ordinal zero");
                }
            } else {
                if (thunk > std::numeric_limits<std::uint32_t>::max()) {
                    throw ApplicationError("name import RVA does not fit in 32 bits");
                }
                const auto name_rva = static_cast<std::uint32_t>(thunk);
                symbol.hint = reader.rva_structure<std::uint16_t>(name_rva);
                symbol.name = reader.rva_string(name_rva + sizeof(std::uint16_t));
            }
            module.symbols.push_back(std::move(symbol));
        }
        if (!thunk_terminated) {
            throw ApplicationError("import thunk table is not terminated");
        }
        plan.imports.push_back(std::move(module));
    }
    if (!terminated) {
        throw ApplicationError("import descriptor table is not terminated within its directory");
    }
}

struct DelayImportDescriptor {
    std::uint32_t attributes{};
    std::uint32_t dll_name{};
    std::uint32_t module_handle{};
    std::uint32_t import_address_table{};
    std::uint32_t import_name_table{};
    std::uint32_t bound_import_table{};
    std::uint32_t unload_import_table{};
    std::uint32_t timestamp{};
};

void parse_delay_imports(
    const ImageReader& reader,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    const IMAGE_DATA_DIRECTORY& directory,
    PortableExecutableMappingPlan& plan) {
    if (!directory_present(directory)) {
        return;
    }
    const auto to_rva = [&](std::uint32_t value, bool fields_are_rvas) -> std::uint32_t {
        if (value == 0 || fields_are_rvas) {
            return value;
        }
        if (value < optional_header.ImageBase ||
            static_cast<std::uint64_t>(value) - optional_header.ImageBase >=
                optional_header.SizeOfImage) {
            throw ApplicationError("delay import VA lies outside the preferred image");
        }
        return static_cast<std::uint32_t>(value - optional_header.ImageBase);
    };
    const auto thunk_to_rva = [&](std::uint64_t value, bool fields_are_rvas) -> std::uint32_t {
        if (fields_are_rvas) {
            if (value > std::numeric_limits<std::uint32_t>::max()) {
                throw ApplicationError("delay import name RVA does not fit in 32 bits");
            }
            return static_cast<std::uint32_t>(value);
        }
        if (value < optional_header.ImageBase ||
            value - optional_header.ImageBase >= optional_header.SizeOfImage) {
            throw ApplicationError("delay import name VA lies outside the preferred image");
        }
        return static_cast<std::uint32_t>(value - optional_header.ImageBase);
    };

    bool terminated = false;
    for (std::size_t module_index = 0;
         (module_index + 1) * sizeof(DelayImportDescriptor) <= directory.Size;
         ++module_index) {
        const auto descriptor = reader.rva_structure<DelayImportDescriptor>(
            directory.VirtualAddress +
            static_cast<std::uint32_t>(module_index * sizeof(DelayImportDescriptor)));
        if (descriptor.attributes == 0 && descriptor.dll_name == 0 &&
            descriptor.module_handle == 0 && descriptor.import_address_table == 0 &&
            descriptor.import_name_table == 0 && descriptor.bound_import_table == 0 &&
            descriptor.unload_import_table == 0 && descriptor.timestamp == 0) {
            terminated = true;
            break;
        }
        if ((descriptor.attributes & ~1U) != 0) {
            throw ApplicationError("delay import descriptor has unknown attributes");
        }
        const bool fields_are_rvas = (descriptor.attributes & 1U) != 0;
        const auto name_rva = to_rva(descriptor.dll_name, fields_are_rvas);
        const auto iat_rva = to_rva(descriptor.import_address_table, fields_are_rvas);
        auto lookup_rva = to_rva(descriptor.import_name_table, fields_are_rvas);
        if (name_rva == 0 || iat_rva == 0) {
            throw ApplicationError("delay import is missing its DLL name or IAT");
        }
        if (lookup_rva == 0) {
            lookup_rva = iat_rva;
        }

        ImportModulePlan module;
        module.name = reader.rva_string(name_rva, 512);
        module.module_handle_rva = to_rva(descriptor.module_handle, fields_are_rvas);
        module.delayed = true;
        bool thunk_terminated = false;
        for (std::size_t symbol_index = 0; symbol_index < 65'536; ++symbol_index) {
            const auto offset64 = symbol_index * sizeof(std::uint64_t);
            if (offset64 > std::numeric_limits<std::uint32_t>::max()) {
                throw ApplicationError("delay import table offset overflowed");
            }
            const auto offset = static_cast<std::uint32_t>(offset64);
            std::uint32_t current_lookup{};
            std::uint32_t current_iat{};
            if (!checked_add(lookup_rva, offset, current_lookup) ||
                !checked_add(iat_rva, offset, current_iat) ||
                static_cast<std::uint64_t>(current_iat) + sizeof(std::uint64_t) >
                    optional_header.SizeOfImage) {
                throw ApplicationError("delay import thunk table exceeds SizeOfImage");
            }
            const auto thunk = reader.rva_structure<std::uint64_t>(current_lookup);
            if (thunk == 0) {
                thunk_terminated = true;
                break;
            }
            ImportSymbolPlan symbol;
            symbol.address_table_rva = current_iat;
            if ((thunk & IMAGE_ORDINAL_FLAG64) != 0) {
                symbol.by_ordinal = true;
                symbol.ordinal = static_cast<std::uint16_t>(thunk & 0xffffU);
                if (symbol.ordinal == 0) {
                    throw ApplicationError("delay ordinal import uses ordinal zero");
                }
            } else {
                const auto import_name_rva = thunk_to_rva(thunk, fields_are_rvas);
                symbol.hint = reader.rva_structure<std::uint16_t>(import_name_rva);
                symbol.name = reader.rva_string(import_name_rva + sizeof(std::uint16_t));
            }
            module.symbols.push_back(std::move(symbol));
        }
        if (!thunk_terminated) {
            throw ApplicationError("delay import thunk table is not terminated");
        }
        plan.imports.push_back(std::move(module));
    }
    if (!terminated) {
        throw ApplicationError("delay import descriptor table is not terminated");
    }
}

void parse_tls(
    const ImageReader& reader,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    const IMAGE_DATA_DIRECTORY& directory,
    PortableExecutableMappingPlan& plan) {
    if (!directory_present(directory)) {
        return;
    }
    if (directory.Size < sizeof(IMAGE_TLS_DIRECTORY64)) {
        throw ApplicationError("TLS directory is smaller than IMAGE_TLS_DIRECTORY64");
    }
    const auto tls = reader.rva_structure<IMAGE_TLS_DIRECTORY64>(directory.VirtualAddress);
    if (tls.AddressOfCallBacks == 0) {
        return;
    }
    if (tls.AddressOfCallBacks < optional_header.ImageBase ||
        tls.AddressOfCallBacks - optional_header.ImageBase >= optional_header.SizeOfImage) {
        throw ApplicationError("TLS callback table address lies outside the preferred image");
    }
    const auto callback_table_rva = static_cast<std::uint32_t>(
        tls.AddressOfCallBacks - optional_header.ImageBase);
    bool terminated = false;
    for (std::size_t index = 0; index < 1024; ++index) {
        std::uint32_t callback_entry_rva = 0;
        if (!checked_add(
                callback_table_rva,
                static_cast<std::uint32_t>(index * sizeof(std::uint64_t)),
                callback_entry_rva)) {
            throw ApplicationError("TLS callback table RVA overflowed");
        }
        const auto callback = reader.rva_structure<std::uint64_t>(callback_entry_rva);
        if (callback == 0) {
            terminated = true;
            break;
        }
        if (callback < optional_header.ImageBase ||
            callback - optional_header.ImageBase >= optional_header.SizeOfImage) {
            throw ApplicationError("TLS callback address lies outside the preferred image");
        }
        plan.tls_callback_rvas.push_back(
            static_cast<std::uint32_t>(callback - optional_header.ImageBase));
    }
    if (!terminated) {
        throw ApplicationError("TLS callback table is not terminated within 1024 entries");
    }
}

void parse_exceptions(
    const ImageReader& reader,
    const IMAGE_OPTIONAL_HEADER64& optional_header,
    const IMAGE_DATA_DIRECTORY& directory,
    PortableExecutableMappingPlan& plan) {
    if (!directory_present(directory)) {
        return;
    }
    if (directory.Size % sizeof(RUNTIME_FUNCTION) != 0) {
        throw ApplicationError("exception directory is not an array of RUNTIME_FUNCTION entries");
    }
    const auto count = directory.Size / sizeof(RUNTIME_FUNCTION);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto function = reader.rva_structure<RUNTIME_FUNCTION>(
            directory.VirtualAddress + index * sizeof(RUNTIME_FUNCTION));
        if (function.BeginAddress >= function.EndAddress ||
            function.EndAddress > optional_header.SizeOfImage ||
            function.UnwindData >= optional_header.SizeOfImage) {
            throw ApplicationError("exception directory contains an invalid function range");
        }
        plan.exception_functions.push_back({
            function.BeginAddress,
            function.EndAddress,
            function.UnwindData,
        });
    }
}

}

PortableExecutableMappingPlan PortableExecutableMappingPlanner::create_plan(
    std::span<const std::uint8_t> image) const {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) {
        throw ApplicationError("portable executable is smaller than its DOS header");
    }
    IMAGE_DOS_HEADER dos{};
    std::memcpy(&dos, image.data(), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
        throw ApplicationError("portable executable has an invalid DOS header");
    }
    const auto nt_offset = static_cast<std::size_t>(dos.e_lfanew);
    ImageReader preliminary{image, {}};
    const auto signature = preliminary.file_structure<DWORD>(nt_offset);
    if (signature != IMAGE_NT_SIGNATURE) {
        throw ApplicationError("portable executable has an invalid NT signature");
    }
    const auto file_header_offset = nt_offset + sizeof(DWORD);
    const auto file_header = preliminary.file_structure<IMAGE_FILE_HEADER>(file_header_offset);
    if (file_header.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        file_header.NumberOfSections == 0 || file_header.NumberOfSections > 96 ||
        file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
        throw ApplicationError("portable executable is not a supported AMD64 PE32+ image");
    }
    const auto optional_header_offset = file_header_offset + sizeof(IMAGE_FILE_HEADER);
    const auto optional_header = preliminary.file_structure<IMAGE_OPTIONAL_HEADER64>(
        optional_header_offset);
    if (optional_header.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        optional_header.SizeOfImage == 0 ||
        optional_header.SizeOfHeaders == 0 ||
        optional_header.SizeOfHeaders > image.size() ||
        optional_header.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
        optional_header.SectionAlignment == 0 || optional_header.FileAlignment == 0) {
        throw ApplicationError("portable executable has an invalid PE32+ optional header");
    }
    if (optional_header.AddressOfEntryPoint >= optional_header.SizeOfImage &&
        optional_header.AddressOfEntryPoint != 0) {
        throw ApplicationError("entry point lies outside SizeOfImage");
    }

    const auto section_table_offset = optional_header_offset + file_header.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sections;
    sections.reserve(file_header.NumberOfSections);
    for (std::size_t index = 0; index < file_header.NumberOfSections; ++index) {
        sections.push_back(preliminary.file_structure<IMAGE_SECTION_HEADER>(
            section_table_offset + index * sizeof(IMAGE_SECTION_HEADER)));
    }
    validate_sections(image, optional_header, sections);
    ImageReader reader{image, optional_header};
    reader.set_sections(sections);

    PortableExecutableMappingPlan plan;
    plan.preferred_image_base = optional_header.ImageBase;
    plan.size_of_image = optional_header.SizeOfImage;
    plan.size_of_headers = optional_header.SizeOfHeaders;
    plan.entry_point_rva = optional_header.AddressOfEntryPoint;
    for (const auto& section : sections) {
        plan.sections.push_back({
            section_name(section),
            section.VirtualAddress,
            section.Misc.VirtualSize,
            section.PointerToRawData,
            section.SizeOfRawData,
            section_access(section.Characteristics),
            (section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0,
        });
    }

    parse_relocations(
        reader,
        optional_header,
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC],
        plan);
    parse_imports(
        reader,
        optional_header,
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        plan);
    parse_delay_imports(
        reader,
        optional_header,
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT],
        plan);
    parse_tls(
        reader,
        optional_header,
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS],
        plan);
    parse_exceptions(
        reader,
        optional_header,
        optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION],
        plan);

    return plan;
}

application::OperationResult PlanningManualMapper::map_image(
    std::uint32_t process_id,
    std::span<const std::uint8_t> portable_executable) {
    last_plan_.reset();
    if (process_id == 0) {
        return application::OperationResult::fail("target process id cannot be zero");
    }
    try {
        last_plan_ = PortableExecutableMappingPlanner{}.create_plan(portable_executable);
        const auto mapped = makima::process::pe_mapping::manual_map_pe_dll(
            process_id, portable_executable);
        std::ostringstream message;
        message << "PE32+ image mapped into process " << process_id
                << " at 0x" << std::hex << mapped.image_base << std::dec << " ("
                << last_plan_->sections.size() << " sections, "
                << mapped.imported_symbol_count << " imports, "
                << mapped.applied_relocation_count << " relocations, "
                << mapped.invoked_tls_callback_count << " TLS callbacks)";
        return application::OperationResult::ok(message.str());
    } catch (const std::exception& error) {
        return application::OperationResult::fail(error.what());
    }
}

}
