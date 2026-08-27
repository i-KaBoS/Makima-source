#include <cstdint>

namespace makima::application::system {

std::uint32_t initialize_ole_registry_discovery_and_gdi(
    void* request_context,
    std::uint32_t fallback_object) noexcept;

std::uint32_t start_security_platform_runtime(
    void* request_context,
    std::uint32_t application_instance) noexcept {
    return initialize_ole_registry_discovery_and_gdi(
        request_context,
        application_instance);
}

}
