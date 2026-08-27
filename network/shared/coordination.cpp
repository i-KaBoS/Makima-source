#include "network/shared/crypto_resolvers.hpp"

#include <cstring>
#include <new>
#include <string_view>
#include <windows.h>

namespace makima::network::shared {

namespace {

decltype(&BCryptGenRandom) bcrypt_random_import{};

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




decltype(&BCryptGenRandom) resolve_bcrypt_random() noexcept {
    static char* const procedure_name =
        allocate_process_lifetime_ascii("BCryptGenRandom");
    static char* const module_name =
        allocate_process_lifetime_ascii("bcrypt.dll");
    bcrypt_random_import =
        resolve_bcrypt_procedure<decltype(bcrypt_random_import)>(
            module_name, procedure_name);
    return bcrypt_random_import;
}

}
