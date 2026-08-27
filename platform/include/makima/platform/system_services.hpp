#pragma once

#include "makima/application/application.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace makima::platform {

struct PrivilegeResult {
    bool success{};
    bool assigned{};
    std::string message;
};

class TokenPrivilegeManager final {
public:
    [[nodiscard]] PrivilegeResult enable(std::wstring_view privilege_name) const;
    [[nodiscard]] bool current_process_is_elevated() const;
};

struct GraphicsSchedulingCapabilities {
    std::string adapter;
    bool query_succeeded{};
    bool hardware_scheduling_supported{};
    bool hardware_scheduling_enabled{};
    bool hardware_scheduling_enabled_by_default{};
    bool independent_vsync_control{};
};

struct EnvironmentReport {
    std::uint64_t physical_memory_bytes{};
    std::uint16_t process_machine{};
    std::uint16_t native_machine{};
    bool debugger_present{};
    bool remote_session{};
    bool hypervisor_present{};
    std::vector<std::string> virtualization_indicators;
    std::vector<GraphicsSchedulingCapabilities> graphics_scheduling;
};

class WindowsEnvironmentInspector final {
public:
    [[nodiscard]] EnvironmentReport inspect() const;
    [[nodiscard]] bool has_active_network_adapter() const;
};

class WindowsSystemService final : public application::ISystemService {
public:
    explicit WindowsSystemService(
        std::uint64_t minimum_memory_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL)
        : minimum_memory_bytes_(minimum_memory_bytes) {}

    application::Json check_vm() override;
    application::Json check_ram() override;
    application::Json check_connection() override;

private:
    WindowsEnvironmentInspector inspector_;
    std::uint64_t minimum_memory_bytes_;
};

}
