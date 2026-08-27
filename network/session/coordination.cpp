#include "network/session/crypto_resolvers.hpp"

#include <cstring>
#include <new>
#include <string_view>
#include <windows.h>

namespace makima::network::session {

namespace {

decltype(&BCryptOpenAlgorithmProvider) bcrypt_open_algorithm_provider_import{};
decltype(&BCryptSetProperty) bcrypt_set_property_import{};
decltype(&BCryptGenerateSymmetricKey) bcrypt_generate_symmetric_key_import{};
decltype(&BCryptEncrypt) bcrypt_encrypt_import{};

char* allocate_process_lifetime_ascii(std::string_view value) noexcept {
    auto* output = new (std::nothrow) char[value.size() + 1U];
    if (output == nullptr) return nullptr;
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return output;
}

template <class Procedure>
Procedure resolve_bcrypt_procedure(
    const char* module_name,
    const char* procedure_name) noexcept {
    if (module_name == nullptr || procedure_name == nullptr) return nullptr;
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    const FARPROC address = module == nullptr
        ? nullptr : GetProcAddress(module, procedure_name);
    Procedure procedure{};
    static_assert(sizeof(procedure) == sizeof(address));
    std::memcpy(&procedure, &address, sizeof(procedure));
    return procedure;
}

}





decltype(&BCryptOpenAlgorithmProvider)
resolve_bcrypt_open_algorithm_provider() noexcept {
    static char* const procedure_name =
        allocate_process_lifetime_ascii("BCryptOpenAlgorithmProvider");
    static char* const module_name =
        allocate_process_lifetime_ascii("bcrypt.dll");
    bcrypt_open_algorithm_provider_import =
        resolve_bcrypt_procedure<decltype(bcrypt_open_algorithm_provider_import)>(
            module_name, procedure_name);
    return bcrypt_open_algorithm_provider_import;
}



decltype(&BCryptSetProperty) resolve_bcrypt_set_property() noexcept {
    static char* const procedure_name =
        allocate_process_lifetime_ascii("BCryptSetProperty");
    static char* const module_name =
        allocate_process_lifetime_ascii("bcrypt.dll");
    bcrypt_set_property_import =
        resolve_bcrypt_procedure<decltype(bcrypt_set_property_import)>(
            module_name, procedure_name);
    return bcrypt_set_property_import;
}



decltype(&BCryptGenerateSymmetricKey)
resolve_bcrypt_generate_symmetric_key() noexcept {
    static char* const procedure_name =
        allocate_process_lifetime_ascii("BCryptGenerateSymmetricKey");
    static char* const module_name =
        allocate_process_lifetime_ascii("bcrypt.dll");
    bcrypt_generate_symmetric_key_import =
        resolve_bcrypt_procedure<decltype(bcrypt_generate_symmetric_key_import)>(
            module_name, procedure_name);
    return bcrypt_generate_symmetric_key_import;
}



decltype(&BCryptEncrypt) resolve_bcrypt_encrypt() noexcept {
    static char* const procedure_name =
        allocate_process_lifetime_ascii("BCryptEncrypt");
    static char* const module_name =
        allocate_process_lifetime_ascii("bcrypt.dll");
    bcrypt_encrypt_import =
        resolve_bcrypt_procedure<decltype(bcrypt_encrypt_import)>(
            module_name, procedure_name);
    return bcrypt_encrypt_import;
}

}
