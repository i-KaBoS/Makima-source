#pragma once

#include <string>

namespace makima::application {

struct VirtualMachineAssessment {
    bool detected{};
    std::string reason;
    std::string evidence;
};

struct StartupSecurityAssessment {
    bool detected{};
    std::string check_id;
    std::string check_json;
};




VirtualMachineAssessment* inspect_virtual_machine_indicators(
    VirtualMachineAssessment* output) noexcept;

StartupSecurityAssessment* inspect_startup_debug_indicators(
    StartupSecurityAssessment* output) noexcept;

void install_fatal_exception_boundary() noexcept;

}
