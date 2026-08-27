#include "payload/auth_mapping/auth_mapping.hpp"

#include <windows.h>

namespace makima::payload::auth_mapping {

char* allocate_create_file_mapping_w_import(
    const std::uint8_t* protected_source);
char* allocate_mapping_kernel_module_name(std::int64_t protected_source);

namespace {

FARPROC create_file_mapping_import = nullptr;

}



void resolve_create_file_mapping_import() noexcept {
    static const char* const api_name = allocate_create_file_mapping_w_import(
        reinterpret_cast<const std::uint8_t*>(0x1414D8EEEull));
    static const char* const module_name = allocate_mapping_kernel_module_name(
        0x1414D8F02ll);
    HMODULE kernel32 = GetModuleHandleA(module_name);
    if (kernel32 == nullptr) kernel32 = LoadLibraryA(module_name);
    create_file_mapping_import =
        kernel32 == nullptr ? nullptr : GetProcAddress(kernel32, api_name);
}

void clear_authenticated_image(AuthenticatedImage& image) noexcept {
    if (!image.bytes.empty()) SecureZeroMemory(image.bytes.data(), image.bytes.size());
    image.bytes.clear();
    image.fingerprint = 0;
    image.authenticated = false;
}

}
