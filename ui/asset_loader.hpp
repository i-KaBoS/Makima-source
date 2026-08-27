#pragma once

#include "makima/application/ui_host.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace makima::ui {

[[nodiscard]] application::MemoryAssetProvider load_assets(
    const std::filesystem::path& directory);



[[nodiscard]] application::MemoryAssetProvider load_embedded_assets(
    void* module_handle = nullptr);

[[nodiscard]] std::filesystem::path executable_asset_directory();

struct AssetArchiveEntry {
    std::uint64_t offset{};
    std::uint64_t size{};
    std::vector<std::uint32_t> blocks;
};



[[nodiscard]] std::vector<AssetArchiveEntry> parse_asset_archive_directory(
    std::span<const std::uint8_t> archive,
    std::uint64_t expected_archive_bytes = 0);

}
