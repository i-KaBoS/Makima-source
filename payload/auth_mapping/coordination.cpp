#include "payload/auth_mapping/auth_mapping.hpp"

#include <windows.h>

#include <cstring>
#include <string>

namespace makima::payload::auth_mapping {




[[nodiscard]] bool mapping_token_equals(
    const std::string& stored,
    const char* token) noexcept {
    const std::size_t token_size = std::strlen(token);
    return stored.size() == token_size &&
        std::memcmp(stored.data(), token, token_size) == 0;
}



[[nodiscard]] bool mapping_token_contains_from(
    const std::string& stored,
    const char* token,
    std::size_t start) noexcept {
    const std::size_t token_size = std::strlen(token);
    if (start > stored.size()) return false;
    return stored.find(token, start, token_size) != std::string::npos;
}




[[nodiscard]] FARPROC resolve_mapping_import_from_loaded_module(
    const char* module_name,
    const char* import_name) noexcept {
    if (module_name == nullptr || import_name == nullptr) return nullptr;
    const HMODULE module = GetModuleHandleA(module_name);
    return module == nullptr ? nullptr : GetProcAddress(module, import_name);
}

[[nodiscard]] bool mapping_result_matches(
    const AuthenticatedImage& image,
    std::span<const std::byte> expected) noexcept {
    return image.authenticated && image.bytes.size() == expected.size() &&
        payload_fingerprint(expected) == image.fingerprint &&
        constant_time_equal(std::span<const std::byte>{image.bytes}, expected);
}

}
