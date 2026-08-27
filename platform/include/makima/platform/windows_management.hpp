#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace makima::platform {

struct ServiceStatus {
    bool installed{};
    std::uint32_t state{};
    std::uint32_t process_id{};
};

struct ServiceCleanupResult {
    bool service_was_present{};
    bool service_stopped{};
    bool service_deleted{};
    bool driver_file_was_present{};
    bool driver_file_deleted{};
};

[[nodiscard]] ServiceStatus query_service_status(std::wstring_view service_name);
[[nodiscard]] ServiceCleanupResult cleanup_stale_winmeminfo(bool delete_driver_file);
[[nodiscard]] bool register_makima_url_protocol(
    const std::filesystem::path& executable_path);

}
