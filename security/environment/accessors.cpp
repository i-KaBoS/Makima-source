#include "security/environment/environment.hpp"

#include <cstddef>
#include <windows.h>

namespace makima::security::environment {

bool query_cpu_registry_details(
    char* processor_name,
    std::size_t processor_name_capacity,
    DWORD* frequency) noexcept {
    if (processor_name == nullptr || processor_name_capacity == 0 ||
        frequency == nullptr) {
        return false;
    }
    *frequency = 0;

    const RegOpenKeyExAFunction reg_open_key_ex_a =
        resolve_reg_open_key_ex_a_import();
    const RegQueryValueExAFunction reg_query_value_ex_a =
        resolve_reg_query_value_ex_a_import();
    const RegCloseKeyFunction reg_close_key = resolve_reg_close_key_import();
    static const char* const registry_path = allocate_cpu_registry_key_path(
        reinterpret_cast<const std::uint8_t*>(0x1414DD32Dull));
    static const char* const frequency_value_name = allocate_cpu_frequency_value_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD372ull));
    static const char* const processor_name_value_name =
        allocate_processor_name_value_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD35Dull));

    HKEY processor_key = nullptr;
    const LSTATUS open_status = reg_open_key_ex_a(
        HKEY_LOCAL_MACHINE,
        registry_path,
        0,
        KEY_READ,
        &processor_key);
    if (open_status != ERROR_SUCCESS) return false;

    DWORD processor_name_size = static_cast<DWORD>(processor_name_capacity);
    reg_query_value_ex_a(
        processor_key,
        processor_name_value_name,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(processor_name),
        &processor_name_size);

    DWORD frequency_size = sizeof(*frequency);
    const LSTATUS frequency_status = reg_query_value_ex_a(
        processor_key,
        frequency_value_name,
        nullptr,
        nullptr,
        reinterpret_cast<LPBYTE>(frequency),
        &frequency_size);
    reg_close_key(processor_key);
    return frequency_status == ERROR_SUCCESS;
}

}
