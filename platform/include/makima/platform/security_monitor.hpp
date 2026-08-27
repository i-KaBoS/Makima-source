#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace makima::platform {

struct ProcessRecord {
    std::uint64_t process_id{};
    std::uint32_t parent_process_id{};
    std::uint32_t thread_count{};
    std::string image_name;
};

[[nodiscard]] std::string format_process_record_json(const ProcessRecord& process);

struct BlockedProcessFinding {
    ProcessRecord process;
    std::string matched_name;
};

class ProcessInventory final {
public:
    [[nodiscard]] std::vector<ProcessRecord> snapshot() const;
    [[nodiscard]] std::optional<BlockedProcessFinding> find_first(
        std::span<const std::string_view> blocked_names) const;
};

struct DesktopTimingReport {
    bool composition_enabled{};
    std::uint64_t refresh_counter{};
    std::uint64_t qpc_refresh_period{};
    std::uint64_t qpc_vblank{};
};

[[nodiscard]] DesktopTimingReport query_desktop_timing();

}
