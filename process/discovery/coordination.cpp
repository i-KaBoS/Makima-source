#include "process/discovery/discovery.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <ranges>
#include <string_view>
#include <utility>

namespace makima::process::discovery {

namespace {

FARPROC create_event_import = nullptr;
FARPROC set_event_import = nullptr;
FARPROC wait_for_single_object_import = nullptr;
FARPROC bcrypt_generate_key_pair_import = nullptr;
FARPROC bcrypt_finalize_key_pair_import = nullptr;
FARPROC bcrypt_export_key_import = nullptr;
FARPROC bcrypt_import_key_pair_import = nullptr;
FARPROC bcrypt_secret_agreement_import = nullptr;
FARPROC bcrypt_derive_key_import = nullptr;
FARPROC bcrypt_destroy_secret_import = nullptr;

}



void resolve_create_event_import() noexcept {
    static const char* const api_name = allocate_create_event_w(
        reinterpret_cast<const std::byte*>(0x1414D90D5ull));
    static const char* const module_name = allocate_kernel32_for_create_event(
        reinterpret_cast<const std::uint8_t*>(0x1414D90E3ull));
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    create_event_import = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_set_event_import() noexcept {
    static const char* const api_name = allocate_set_event(
        reinterpret_cast<const std::byte*>(0x1414D90F1ull));
    static const char* const module_name = allocate_kernel32_dll(
        0x1414D90FBll);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    set_event_import = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_wait_for_single_object_import() noexcept {
    static const char* const api_name = allocate_wait_for_single_object(
        0x1414D9109ll, 0);
    static const char* const module_name =
        allocate_kernel32_dll_for_wait_for_single_object(0x1414D911Ell);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    wait_for_single_object_import = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}



void resolve_bcrypt_generate_key_pair_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_generate_key_pair_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptGenerateKeyPair");
}


void resolve_bcrypt_finalize_key_pair_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_finalize_key_pair_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptFinalizeKeyPair");
}


void resolve_bcrypt_export_key_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_export_key_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptExportKey");
}


void resolve_bcrypt_import_key_pair_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_import_key_pair_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptImportKeyPair");
}


void resolve_bcrypt_secret_agreement_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_secret_agreement_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptSecretAgreement");
}


void resolve_bcrypt_derive_key_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_derive_key_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptDeriveKey");
}


void resolve_bcrypt_destroy_secret_import() noexcept {
    HMODULE module = GetModuleHandleA("bcrypt.dll");
    if (module == nullptr) module = LoadLibraryA("bcrypt.dll");
    bcrypt_destroy_secret_import = module == nullptr
        ? nullptr : GetProcAddress(module, "BCryptDestroySecret");
}

}
