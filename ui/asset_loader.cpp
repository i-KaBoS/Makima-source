#include "ui/asset_loader.hpp"

#include "makima/application/common.hpp"
#include "resources/resource_ids.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <stdexcept>
#include <utility>

namespace makima::ui {
namespace {

struct AssetDescription {
    std::string_view source_file, route;
    std::string_view mime_type;
    std::uint16_t resource_id;
};

constexpr std::array descriptions{
    AssetDescription{"index.html", "index.html", "text/html; charset=utf-8", IDR_APPLICATION_HTML},
    AssetDescription{"app.css", "app.css", "text/css; charset=utf-8", IDR_APPLICATION_CSS},
    AssetDescription{
        "app.js", "app.js", "application/javascript", IDR_APPLICATION_JAVASCRIPT},
    AssetDescription{
        "startup_check.html", "_splash.html", "text/html; charset=utf-8", IDR_STARTUP_CHECK_HTML},
    AssetDescription{"logo.png", "logo.png", "image/png", IDR_APPLICATION_LOGO},
};



constexpr std::array<std::uint8_t, 32> asset_xor_key{
    0x2f, 0xec, 0x4b, 0xd2, 0x67, 0x8a, 0xd2, 0x29,
    0x69, 0xf4, 0x01, 0x0c, 0xe9, 0xbb, 0x10, 0x4a,
    0x68, 0x8d, 0x65, 0x83, 0xc4, 0x4e, 0x3c, 0xf5,
    0xf2, 0x8c, 0x18, 0xe4, 0xdb, 0x97, 0xb1, 0x38,
};

application::Bytes read_file(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        throw application::ApplicationError("cannot open UI asset: " + path.string());
    }
    return application::Bytes(
        std::istreambuf_iterator<char>{stream},
        std::istreambuf_iterator<char>{});
}

class MappedImage final {
public:
    explicit MappedImage(void* module_handle) {
        module_ = module_handle != nullptr
            ? static_cast<HMODULE>(module_handle)
            : GetModuleHandleW(nullptr);
        if (module_ == nullptr) {
            throw application::ApplicationError("cannot locate the loaded application image");
        }

        base_ = reinterpret_cast<const std::uint8_t*>(module_);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
            dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
            dos->e_lfanew > 1024 * 1024) {
            throw application::ApplicationError("loaded application has an invalid DOS header");
        }

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base_ + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
            nt->OptionalHeader.SizeOfImage < sizeof(IMAGE_DOS_HEADER)) {
            throw application::ApplicationError("loaded application has an invalid PE header");
        }
        image_size_ = nt->OptionalHeader.SizeOfImage;
        resources_ = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
        if (!contains(resources_.VirtualAddress, resources_.Size) ||
            resources_.Size < sizeof(IMAGE_RESOURCE_DIRECTORY)) {
            throw application::ApplicationError("loaded application has no valid resource tree");
        }
    }

    [[nodiscard]] application::Bytes resource(
        std::uint16_t type_id,
        std::uint16_t resource_id,
        std::uint16_t language_id = MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)) const {
        const auto* root = at_resource_offset<IMAGE_RESOURCE_DIRECTORY>(0);
        const auto* type = find_id(root, type_id);
        const auto* names = directory(type);
        const auto* name = find_id(names, resource_id);
        const auto* languages = directory(name);
        const auto* language = find_id(languages, language_id);
        if (language == nullptr) {
            language = first_id(languages);
        }
        if (language == nullptr || language->DataIsDirectory != 0) {
            throw application::ApplicationError(
                "embedded UI resource " + std::to_string(resource_id) + " is missing");
        }

        const auto* data = at_resource_offset<IMAGE_RESOURCE_DATA_ENTRY>(
            language->OffsetToData);
        if (!contains(data->OffsetToData, data->Size)) {
            throw application::ApplicationError(
                "embedded UI resource " + std::to_string(resource_id) + " is invalid");
        }
        const auto* first = base_ + data->OffsetToData;
        return application::Bytes{first, first + data->Size};
    }

private:
    [[nodiscard]] bool contains(std::uint32_t offset, std::size_t size) const noexcept {
        return offset <= image_size_ && size <= image_size_ - offset;
    }

    template <class T>
    [[nodiscard]] const T* at_resource_offset(std::uint32_t offset) const {
        if (offset > resources_.Size || sizeof(T) > resources_.Size - offset ||
            offset > std::numeric_limits<std::uint32_t>::max() - resources_.VirtualAddress ||
            !contains(resources_.VirtualAddress + offset, sizeof(T))) {
            throw application::ApplicationError("loaded application has a damaged resource tree");
        }
        return reinterpret_cast<const T*>(base_ + resources_.VirtualAddress + offset);
    }

    [[nodiscard]] const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries(
        const IMAGE_RESOURCE_DIRECTORY* directory) const {
        const auto directory_offset = static_cast<std::uint32_t>(
            reinterpret_cast<const std::uint8_t*>(directory) -
            (base_ + resources_.VirtualAddress));
        const auto count = static_cast<std::size_t>(directory->NumberOfNamedEntries) +
            directory->NumberOfIdEntries;
        const auto entries_offset = directory_offset + sizeof(IMAGE_RESOURCE_DIRECTORY);
        if (count > std::numeric_limits<std::uint32_t>::max() /
                sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) ||
            entries_offset > resources_.Size ||
            count * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) >
                resources_.Size - entries_offset) {
            throw application::ApplicationError("loaded application has a damaged resource tree");
        }
        return at_resource_offset<IMAGE_RESOURCE_DIRECTORY_ENTRY>(entries_offset);
    }

    [[nodiscard]] const IMAGE_RESOURCE_DIRECTORY_ENTRY* find_id(
        const IMAGE_RESOURCE_DIRECTORY* directory,
        std::uint16_t id) const {
        if (directory == nullptr) {
            return nullptr;
        }
        const auto count = static_cast<std::size_t>(directory->NumberOfNamedEntries) +
            directory->NumberOfIdEntries;
        const auto* entry = entries(directory);
        for (std::size_t index = 0; index < count; ++index) {
            if (entry[index].NameIsString == 0 && entry[index].Id == id) {
                return entry + index;
            }
        }
        return nullptr;
    }

    [[nodiscard]] const IMAGE_RESOURCE_DIRECTORY_ENTRY* first_id(
        const IMAGE_RESOURCE_DIRECTORY* directory) const {
        if (directory == nullptr || directory->NumberOfIdEntries == 0) {
            return nullptr;
        }
        return entries(directory) + directory->NumberOfNamedEntries;
    }

    [[nodiscard]] const IMAGE_RESOURCE_DIRECTORY* directory(
        const IMAGE_RESOURCE_DIRECTORY_ENTRY* entry) const {
        if (entry == nullptr || entry->DataIsDirectory == 0) {
            return nullptr;
        }
        return at_resource_offset<IMAGE_RESOURCE_DIRECTORY>(entry->OffsetToDirectory);
    }

    HMODULE module_{};
    const std::uint8_t* base_{};
    std::size_t image_size_{};
    IMAGE_DATA_DIRECTORY resources_{};
};

application::Bytes decrypt_asset(application::Bytes encrypted) {
    for (std::size_t index = 0; index < encrypted.size(); ++index) {
        encrypted[index] ^= asset_xor_key[index % asset_xor_key.size()];
    }
    return encrypted;
}

struct AssetArchiveParserContext final {
    const std::uint8_t* archive{};
    std::uint64_t archive_bytes{};
    bool valid{};
    std::uint8_t validity_padding[3]{};
    std::uint32_t block_size{};
    std::uint32_t block_count{};
    std::uint32_t directory_bytes{};
    std::uint32_t directory_list_block{};
    std::vector<std::uint32_t> stream_sizes;
    std::vector<std::vector<std::uint32_t>> stream_blocks;
    std::string error;
};

static_assert(offsetof(AssetArchiveParserContext, archive) == 0x00);
static_assert(offsetof(AssetArchiveParserContext, archive_bytes) == 0x08);
static_assert(offsetof(AssetArchiveParserContext, valid) == 0x10);
static_assert(offsetof(AssetArchiveParserContext, block_size) == 0x14);
static_assert(offsetof(AssetArchiveParserContext, block_count) == 0x18);
static_assert(offsetof(AssetArchiveParserContext, directory_bytes) == 0x1c);
static_assert(offsetof(AssetArchiveParserContext, directory_list_block) == 0x20);
static_assert(offsetof(AssetArchiveParserContext, stream_sizes) == 0x28);
static_assert(offsetof(AssetArchiveParserContext, stream_blocks) == 0x40);
static_assert(offsetof(AssetArchiveParserContext, error) == 0x58);

std::uint32_t read_archive_u32(const std::uint8_t* bytes) noexcept {
    std::uint32_t value{};
    std::memcpy(&value, bytes, sizeof(value));
    return value;
}

std::uint64_t fail_archive_parse(
    AssetArchiveParserContext& context,
    std::string_view message) {
    context.error.assign(message);
    return 0;
}



std::uint64_t parse_archive_directory_blocks(AssetArchiveParserContext* context) {
    if (context == nullptr || context->archive == nullptr || context->block_size == 0) {
        return 0;
    }

    context->stream_sizes.clear();
    context->stream_blocks.clear();
    context->error.clear();

    const std::uint64_t directory_block_count =
        static_cast<std::uint32_t>(
            context->directory_bytes + context->block_size - 1U) /
        context->block_size;
    const std::uint64_t directory_list_bytes =
        directory_block_count * sizeof(std::uint32_t);
    if (directory_list_bytes > context->block_size) {
        return fail_archive_parse(*context, "directory block list too large");
    }

    const std::uint64_t list_offset =
        static_cast<std::uint64_t>(context->directory_list_block) * context->block_size;
    if (list_offset > context->archive_bytes ||
        directory_list_bytes > context->archive_bytes - list_offset) {
        return fail_archive_parse(*context, "dir block OOB");
    }

    std::vector<std::uint8_t> directory(context->directory_bytes);
    std::size_t destination = 0;
    for (std::uint64_t index = 0; index < directory_block_count; ++index) {
        const std::uint32_t block = read_archive_u32(
            context->archive + list_offset + index * sizeof(std::uint32_t));
        if (block >= context->block_count) {
            return fail_archive_parse(*context, "dir block OOB");
        }

        const std::uint64_t source =
            static_cast<std::uint64_t>(block) * context->block_size;
        const std::size_t copy_bytes = std::min<std::size_t>(
            context->block_size,
            directory.size() - destination);
        if (source > context->archive_bytes ||
            copy_bytes > context->archive_bytes - source) {
            return fail_archive_parse(*context, "dir block OOB");
        }
        std::memcpy(directory.data() + destination, context->archive + source, copy_bytes);
        destination += copy_bytes;
    }

    if (directory.size() < sizeof(std::uint32_t)) {
        return fail_archive_parse(*context, "directory truncated");
    }

    const std::uint32_t stream_count = read_archive_u32(directory.data());
    constexpr std::uint32_t maximum_streams = 0x100000;
    if (stream_count > maximum_streams) {
        return fail_archive_parse(*context, "absurd stream count");
    }

    const std::uint64_t size_table_bytes =
        sizeof(std::uint32_t) +
        static_cast<std::uint64_t>(stream_count) * sizeof(std::uint32_t);
    if (size_table_bytes > directory.size()) {
        return fail_archive_parse(*context, "directory truncated (sizes)");
    }

    context->stream_sizes.resize(stream_count);
    context->stream_blocks.resize(stream_count);
    for (std::uint32_t stream = 0; stream < stream_count; ++stream) {
        context->stream_sizes[stream] = read_archive_u32(
            directory.data() + sizeof(std::uint32_t) +
            static_cast<std::size_t>(stream) * sizeof(std::uint32_t));
    }

    std::uint64_t cursor = size_table_bytes;
    for (std::uint32_t stream = 0; stream < stream_count; ++stream) {
        const std::uint32_t stream_size = context->stream_sizes[stream];
        if (stream_size == std::numeric_limits<std::uint32_t>::max()) {
            continue;
        }

        const std::uint64_t stream_block_count =
            static_cast<std::uint32_t>(stream_size + context->block_size - 1U) /
            context->block_size;
        const std::uint64_t stream_block_bytes =
            stream_block_count * sizeof(std::uint32_t);
        if (cursor > directory.size() ||
            stream_block_bytes > directory.size() - cursor) {
            return fail_archive_parse(*context, "directory truncated (blocks)");
        }

        auto& blocks = context->stream_blocks[stream];
        blocks.resize(static_cast<std::size_t>(stream_block_count));
        for (std::uint64_t block_index = 0;
             block_index < stream_block_count;
             ++block_index) {
            const std::uint32_t block = read_archive_u32(
                directory.data() + cursor + block_index * sizeof(std::uint32_t));
            if (block >= context->block_count) {
                return fail_archive_parse(*context, "stream block OOB");
            }
            blocks[static_cast<std::size_t>(block_index)] = block;
        }
        cursor += stream_block_bytes;
    }

    return 1;
}

}

std::vector<AssetArchiveEntry> parse_asset_archive_directory(
    std::span<const std::uint8_t> archive,
    std::uint64_t expected_archive_bytes) {
    constexpr std::size_t block_size_offset = 0x20;
    constexpr std::size_t block_count_offset = 0x28;
    constexpr std::size_t directory_bytes_offset = 0x2c;
    constexpr std::size_t directory_list_block_offset = 0x34;
    constexpr std::size_t minimum_header_bytes = 0x38;
    if (archive.size() < minimum_header_bytes ||
        (expected_archive_bytes != 0 && expected_archive_bytes != archive.size())) {
        throw application::ApplicationError("directory truncated");
    }

    AssetArchiveParserContext context{};
    context.archive = archive.data();
    context.archive_bytes = archive.size();
    context.block_size = read_archive_u32(archive.data() + block_size_offset);
    context.block_count = read_archive_u32(archive.data() + block_count_offset);
    context.directory_bytes = read_archive_u32(archive.data() + directory_bytes_offset);
    context.directory_list_block =
        read_archive_u32(archive.data() + directory_list_block_offset);

    const std::uint64_t described_archive_bytes =
        static_cast<std::uint64_t>(context.block_size) * context.block_count;
    if (context.block_size == 0 ||
        described_archive_bytes != context.archive_bytes ||
        context.directory_list_block >= context.block_count) {
        throw application::ApplicationError("dir block OOB");
    }

    if (parse_archive_directory_blocks(&context) == 0) {
        throw application::ApplicationError(
            context.error.empty() ? "directory truncated" : context.error);
    }
    context.valid = true;

    std::vector<AssetArchiveEntry> entries;
    entries.reserve(context.stream_sizes.size());
    for (std::size_t stream = 0; stream < context.stream_sizes.size(); ++stream) {
        const auto& blocks = context.stream_blocks[stream];
        const std::uint64_t first_offset = blocks.empty()
            ? 0
            : static_cast<std::uint64_t>(blocks.front()) * context.block_size;
        entries.push_back(AssetArchiveEntry{
            first_offset,
            context.stream_sizes[stream],
            blocks});
    }
    return entries;
}

application::MemoryAssetProvider load_assets(const std::filesystem::path& directory) {
    application::MemoryAssetProvider assets;
    for (const auto& description : descriptions) {
        const auto path = directory / std::filesystem::path{description.source_file};
        assets.add(
            "/" + std::string{description.route},
            std::string{description.mime_type},
            read_file(path));
    }
    return assets;
}

application::MemoryAssetProvider load_embedded_assets(void* module_handle) {
    const MappedImage image{module_handle};
    application::MemoryAssetProvider assets;
    for (const auto& description : descriptions) {
        assets.add(
            "/" + std::string{description.route},
            std::string{description.mime_type},
            decrypt_asset(image.resource(10, description.resource_id)));
    }
    return assets;
}

std::filesystem::path executable_asset_directory() {
    std::wstring path(32768, L'\0');
    const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) {
        throw application::ApplicationError("cannot locate the Makima Loader executable");
    }
    path.resize(length);
    return std::filesystem::path{path}.parent_path() / L"ui";
}

}
