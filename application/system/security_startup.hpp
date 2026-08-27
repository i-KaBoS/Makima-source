#pragma once

#include <cstdint>

namespace makima::application::system {

std::uint32_t initialize_ole_registry_discovery_and_gdi(
    void* request_context,
    std::uint32_t application_instance) noexcept;

}
