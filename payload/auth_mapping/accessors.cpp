#include "payload/auth_mapping/auth_mapping.hpp"

namespace makima::payload::auth_mapping {

std::span<const std::byte> authenticated_bytes(const AuthenticatedImage& image) noexcept {
    if (!image.authenticated) return {};
    return image.bytes;
}

}
