#pragma once

#include "makima/application/launch_coordinator.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace makima::platform {

enum class SectionAccess : std::uint8_t {
    none = 0,
    read = 1,
    write = 2,
    execute = 4,
};

constexpr SectionAccess operator|(SectionAccess left, SectionAccess right) noexcept {
    return static_cast<SectionAccess>(
        static_cast<std::uint8_t>(left) | static_cast<std::uint8_t>(right));
}

struct SectionPlan {
    std::string name;
    std::uint32_t virtual_address{};
    std::uint32_t virtual_size{};
    std::uint32_t raw_offset{};
    std::uint32_t raw_size{};
    SectionAccess access{SectionAccess::none};
    bool discardable{};
};

struct RelocationPlan {
    std::uint32_t target_rva{};
    std::uint16_t type{};
};

struct ImportSymbolPlan {
    std::string name;
    std::uint16_t ordinal{};
    std::uint16_t hint{};
    std::uint32_t address_table_rva{};
    bool by_ordinal{};
};

struct ImportModulePlan {
    std::string name;
    std::vector<ImportSymbolPlan> symbols;
    std::uint32_t module_handle_rva{};
    bool delayed{};
};

struct ExceptionFunctionPlan {
    std::uint32_t begin_rva{};
    std::uint32_t end_rva{};
    std::uint32_t unwind_info_rva{};
};

struct PortableExecutableMappingPlan {
    std::uint64_t preferred_image_base{};
    std::uint32_t size_of_image{};
    std::uint32_t size_of_headers{};
    std::uint32_t entry_point_rva{};
    std::vector<SectionPlan> sections;
    std::vector<RelocationPlan> relocations;
    std::vector<ImportModulePlan> imports;
    std::vector<std::uint32_t> tls_callback_rvas;
    std::vector<ExceptionFunctionPlan> exception_functions;
    std::vector<std::string> unsupported_execution_steps;
};

class PortableExecutableMappingPlanner final {
public:
    [[nodiscard]] PortableExecutableMappingPlan create_plan(
        std::span<const std::uint8_t> image) const;
};

class PlanningManualMapper final : public application::IManualMapper {
public:
    application::OperationResult map_image(
        std::uint32_t process_id,
        std::span<const std::uint8_t> portable_executable) override;

    [[nodiscard]] const std::optional<PortableExecutableMappingPlan>& last_plan() const noexcept {
        return last_plan_;
    }

private:
    std::optional<PortableExecutableMappingPlan> last_plan_;
};

}
