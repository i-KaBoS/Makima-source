#include "payload/auth_mapping/auth_mapping.hpp"

#include <windows.h>

#include <exception>

namespace makima::payload::auth_mapping {

char* allocate_map_view_api_name(std::int64_t protected_source);
char* allocate_kernel32_for_map_view_of_file(
    const std::uint8_t* protected_source);
char* allocate_unmap_view_api_name(std::int64_t protected_source);
char* allocate_kernel32_for_unmap_view_of_file(
    const std::uint8_t* protected_source);

namespace {

FARPROC map_view_of_file_import = nullptr;
FARPROC unmap_view_of_file_import = nullptr;

}



void resolve_map_view_of_file_import() noexcept {
    static const char* const api_name = allocate_map_view_api_name(0x1414D8F10ll);
    static const char* const module_name = allocate_kernel32_for_map_view_of_file(
        reinterpret_cast<const std::uint8_t*>(0x1414D8F1Full));
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    map_view_of_file_import = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_unmap_view_of_file_import() noexcept {
    static const char* const api_name = allocate_unmap_view_api_name(0x1414D8F2Dll);
    static const char* const module_name = allocate_kernel32_for_unmap_view_of_file(
        reinterpret_cast<const std::uint8_t*>(0x1414D8F3Eull));
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    unmap_view_of_file_import = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}

bool map_authenticated_image(
    std::span<const std::byte> image,
    std::span<const std::byte> supplied_tag,
    std::span<const std::byte> expected_tag,
    const MappingPolicy& policy,
    AuthenticatedImage& result) noexcept {
    clear_authenticated_image(result);
    if (image.empty() || image.size() > policy.maximum_image_size) return false;
    if (!constant_time_equal(supplied_tag, expected_tag)) return false;
    if (policy.require_pe_image && !has_valid_pe_layout(image)) return false;

    try {
        result.bytes.assign(image.begin(), image.end());
        result.fingerprint = payload_fingerprint(result.bytes);
        result.authenticated = true;
        return true;
    } catch (const std::exception&) {
        clear_authenticated_image(result);
        return false;
    }
}

}
