#include "security/environment/environment.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include <shlobj.h>

namespace makima::security::environment {

namespace {

FARPROC resolve_dynamic_import(const char* module_name, const char* export_name) noexcept {
    const HMODULE module = LoadLibraryA(module_name);
    return module == nullptr ? nullptr : GetProcAddress(module, export_name);
}

}






GetSystemInfoFunction get_system_info_binding =
    reinterpret_cast<GetSystemInfoFunction>(
        resolve_dynamic_import("kernel32.dll", "GetSystemInfo"));

static bool append_json_escape(std::string& output, std::string_view input) {
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char value : input) {
        switch (value) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (value < 0x20U) {
                output += "\\u00";
                output.push_back(hex[value >> 4U]);
                output.push_back(hex[value & 0x0fU]);
            } else {
                output.push_back(static_cast<char>(value));
            }
        }
    }
    return true;
}



bool locate_internet_cache_directory(
    wchar_t* destination,
    std::size_t destination_capacity) noexcept {
    if (destination == nullptr || destination_capacity == 0) return false;
    destination[0] = L'\0';

    wchar_t local_app_data[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(
            nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, local_app_data))) {
        return false;
    }

    static const wchar_t* const app_ex_format = allocate_content_app_ex_cache_path_format(
        reinterpret_cast<const std::uint16_t*>(0x1414DD050ull));
    if (_snwprintf_s(
            destination,
            destination_capacity,
            _TRUNCATE,
            app_ex_format,
            local_app_data) < 0) {
        return false;
    }
    if (GetFileAttributesW(destination) != INVALID_FILE_ATTRIBUTES) return true;

    static const wchar_t* const cache_format = allocate_internet_cache_path_format(
        reinterpret_cast<const std::uint16_t*>(0x1414DD0ACull));
    return _snwprintf_s(
               destination,
               destination_capacity,
               _TRUNCATE,
               cache_format,
               local_app_data) >= 0;
}



void append_json_string_property(
    std::string* json,
    const char* key,
    const char* value,
    char* first_property_state) {
    static const char* const comma = allocate_json_property_comma_for_string(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2F6ull));
    static const char* const colon = allocate_json_property_colon_for_string(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2F9ull));
    if (*first_property_state == '\0') json->append(comma);
    *first_property_state = '\0';
    json->push_back('"');
    json->append(key);
    json->append(colon);
    append_json_escaped_text(json, value == nullptr ? "" : value);
}



void append_json_integer_property(
    std::string* json,
    const char* key,
    std::int64_t value,
    char* first_property_state) {
    static const char* const comma = allocate_json_property_comma_for_integer(
        reinterpret_cast<const std::uint8_t*>(0x1414DD303ull));
    static const char* const format = allocate_signed_integer_format(
        reinterpret_cast<const std::uint8_t*>(0x1414DD306ull));
    static const char* const colon = allocate_json_property_colon_for_integer(
        reinterpret_cast<const std::uint8_t*>(0x1414DD30Cull));
    if (*first_property_state == '\0') json->append(comma);
    *first_property_state = '\0';
    std::array<char, 32> formatted{};
    std::snprintf(formatted.data(), formatted.size(), format, static_cast<long long>(value));
    json->push_back('"');
    json->append(key);
    json->append(colon);
    json->append(formatted.data());
}



void append_json_boolean_property(
    std::string* json,
    const char* key,
    bool value,
    char* first_property_state) {
    static const char* const comma = allocate_json_property_comma_for_boolean(
        reinterpret_cast<const std::uint8_t*>(0x1414DD40Bull));
    static const char* const colon = allocate_json_property_colon_for_boolean(
        reinterpret_cast<const std::uint8_t*>(0x1414DD40Eull));
    static const char* const true_literal = allocate_json_true_literal(
        reinterpret_cast<const std::uint8_t*>(0x1414DD412ull));
    static const char* const false_literal = allocate_json_false_literal(
        reinterpret_cast<const std::uint8_t*>(0x1414DD418ull));
    if (*first_property_state == '\0') json->append(comma);
    *first_property_state = '\0';
    json->push_back('"');
    json->append(key);
    json->append(colon);
    json->append(value ? true_literal : false_literal);
}



GetSystemTimeFunction resolve_get_system_time_import() noexcept {
    static const char* const export_name = allocate_get_system_time_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE26Dull));
    static const char* const module_name = allocate_kernel32_for_get_system_time(
        reinterpret_cast<const std::uint8_t*>(0x1414DE27Cull));
    return reinterpret_cast<GetSystemTimeFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CoInitializeExFunction resolve_co_initialize_ex_import() noexcept {
    static const char* const export_name = allocate_co_initialize_ex_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE28Aull));
    static const char* const module_name = allocate_ole32_for_co_initialize_ex(
        reinterpret_cast<const std::uint8_t*>(0x1414DE29Aull));
    return reinterpret_cast<CoInitializeExFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CoInitializeSecurityFunction resolve_co_initialize_security_import() noexcept {
    static const char* const export_name = allocate_co_initialize_security_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2A5ull));
    static const char* const module_name = allocate_ole32_for_co_initialize_security(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2BBull));
    return reinterpret_cast<CoInitializeSecurityFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CoCreateInstanceFunction resolve_co_create_instance_import() noexcept {
    static const char* const export_name = allocate_co_create_instance_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2C6ull));
    static const char* const module_name = allocate_ole32_for_co_create_instance(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2D8ull));
    return reinterpret_cast<CoCreateInstanceFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CoSetProxyBlanketFunction resolve_co_set_proxy_blanket_import() noexcept {
    static const char* const export_name = allocate_co_set_proxy_blanket_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2E3ull));
    static const char* const module_name = allocate_ole32_for_co_set_proxy_blanket(
        reinterpret_cast<const std::uint8_t*>(0x1414DE2F6ull));
    return reinterpret_cast<CoSetProxyBlanketFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CreateDxgiFactory1Function resolve_create_dxgi_factory1_import() noexcept {
    static const char* const export_name = allocate_create_dxgi_factory1_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE301ull));
    static const char* const module_name = allocate_dxgi_for_create_dxgi_factory1(
        reinterpret_cast<const std::uint8_t*>(0x1414DE315ull));
    return reinterpret_cast<CreateDxgiFactory1Function>(
        resolve_dynamic_import(module_name, export_name));
}




GetModuleHandleAFunction resolve_get_module_handle_a_import() noexcept {
    static const char* const export_name = allocate_get_module_handle_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE31Full));
    static const char* const module_name = allocate_kernel32_for_get_module_handle_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE331ull));
    return reinterpret_cast<GetModuleHandleAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CoUninitializeFunction resolve_co_uninitialize_import() noexcept {
    static const char* const export_name = allocate_co_uninitialize_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE623ull));
    static const char* const module_name = allocate_ole32_for_co_uninitialize(
        reinterpret_cast<const std::uint8_t*>(0x1414DE633ull));
    return reinterpret_cast<CoUninitializeFunction>(
        resolve_dynamic_import(module_name, export_name));
}



GlobalMemoryStatusExFunction resolve_global_memory_status_ex_import() noexcept {
    static const char* const export_name = allocate_global_memory_status_ex_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD02Aull));
    static const char* const module_name = allocate_kernel32_for_global_memory_status_ex(
        reinterpret_cast<const std::uint8_t*>(0x1414DD040ull));
    return reinterpret_cast<GlobalMemoryStatusExFunction>(
        resolve_dynamic_import(module_name, export_name));
}


RegOpenKeyExAFunction resolve_reg_open_key_ex_a_import() noexcept {
    static const char* const export_name = allocate_reg_open_key_ex_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DCFD2ull));
    static const char* const module_name = allocate_advapi32_for_reg_open_key_ex_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DCFE1ull));
    return reinterpret_cast<RegOpenKeyExAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


RegCloseKeyFunction resolve_reg_close_key_import() noexcept {
    static const char* const export_name = allocate_reg_close_key_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DCFEFull));
    static const char* const module_name = allocate_advapi32_for_reg_close_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DCFFCull));
    return reinterpret_cast<RegCloseKeyFunction>(
        resolve_dynamic_import(module_name, export_name));
}




RegEnumKeyExAFunction resolve_reg_enum_key_ex_a_import() noexcept {
    static const char* const export_name = allocate_reg_enum_key_ex_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE33Full));
    static const char* const module_name = allocate_advapi32_for_reg_enum_key_ex_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE34Eull));
    return reinterpret_cast<RegEnumKeyExAFunction>(
        resolve_dynamic_import(module_name, export_name));
}




D3D11CreateDeviceFunction resolve_d3d11_create_device_import() noexcept {
    static const char* const export_name = allocate_d3d11_create_device_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE35Cull));
    static const char* const module_name = allocate_d3d11_for_create_device(
        reinterpret_cast<const std::uint8_t*>(0x1414DE36Full));
    return reinterpret_cast<D3D11CreateDeviceFunction>(
        resolve_dynamic_import(module_name, export_name));
}



EnumDisplayDevicesAFunction resolve_enum_display_devices_a_import() noexcept {
    static const char* const export_name = allocate_enum_display_devices_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE37Aull));
    static const char* const module_name = allocate_user32_for_enum_display_devices_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE38Full));
    return reinterpret_cast<EnumDisplayDevicesAFunction>(
        resolve_dynamic_import(module_name, export_name));
}




EnumDisplaySettingsAFunction resolve_enum_display_settings_a_import() noexcept {
    static const char* const export_name = allocate_enum_display_settings_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE39Bull));
    static const char* const module_name = allocate_user32_for_enum_display_settings_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE3B1ull));
    return reinterpret_cast<EnumDisplaySettingsAFunction>(
        resolve_dynamic_import(module_name, export_name));
}




SetupDiGetClassDevsAFunction resolve_setup_di_get_class_devs_a_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_get_class_devs_a_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE3BDull));
    static const char* const module_name = allocate_setupapi_for_get_class_devs_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE3D3ull));
    return reinterpret_cast<SetupDiGetClassDevsAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


SetupDiEnumDeviceInfoFunction resolve_setup_di_enum_device_info_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_enum_device_info_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE3E1ull));
    static const char* const module_name = allocate_setupapi_for_enum_device_info(
        reinterpret_cast<const std::uint8_t*>(0x1414DE3F8ull));
    return reinterpret_cast<SetupDiEnumDeviceInfoFunction>(
        resolve_dynamic_import(module_name, export_name));
}


SetupDiOpenDevRegKeyFunction resolve_setup_di_open_dev_reg_key_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_open_dev_reg_key_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE406ull));
    static const char* const module_name = allocate_setupapi_for_open_dev_reg_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DE41Cull));
    return reinterpret_cast<SetupDiOpenDevRegKeyFunction>(
        resolve_dynamic_import(module_name, export_name));
}


SetupDiDestroyDeviceInfoListFunction
resolve_setup_di_destroy_device_info_list_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_destroy_device_info_list_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE42Aull));
    static const char* const module_name =
        allocate_setupapi_for_destroy_device_info_list(
            reinterpret_cast<const std::uint8_t*>(0x1414DE448ull));
    return reinterpret_cast<SetupDiDestroyDeviceInfoListFunction>(
        resolve_dynamic_import(module_name, export_name));
}



HidDGetHidGuidFunction resolve_hid_d_get_hid_guid_import() noexcept {
    static const char* const export_name = allocate_hid_d_get_hid_guid_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE456ull));
    static const char* const module_name = allocate_hid_for_get_hid_guid(
        reinterpret_cast<const std::uint8_t*>(0x1414DE467ull));
    return reinterpret_cast<HidDGetHidGuidFunction>(
        resolve_dynamic_import(module_name, export_name));
}


SetupDiEnumDeviceInterfacesFunction
resolve_setup_di_enum_device_interfaces_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_enum_device_interfaces_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE470ull));
    static const char* const module_name =
        allocate_setupapi_for_enum_device_interfaces(
            reinterpret_cast<const std::uint8_t*>(0x1414DE48Dull));
    return reinterpret_cast<SetupDiEnumDeviceInterfacesFunction>(
        resolve_dynamic_import(module_name, export_name));
}


SetupDiGetDeviceInterfaceDetailAFunction
resolve_setup_di_get_device_interface_detail_a_import() noexcept {
    static const char* const export_name =
        allocate_setup_di_get_device_interface_detail_a_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE49Bull));
    static const char* const module_name =
        allocate_setupapi_for_get_device_interface_detail_a(
            reinterpret_cast<const std::uint8_t*>(0x1414DE4BDull));
    return reinterpret_cast<SetupDiGetDeviceInterfaceDetailAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


CreateFileAFunction resolve_create_file_a_import() noexcept {
    static const char* const export_name = allocate_create_file_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE4CBull));
    static const char* const module_name = allocate_kernel32_for_create_file_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DE4D8ull));
    return reinterpret_cast<CreateFileAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


HidDGetAttributesFunction resolve_hid_d_get_attributes_import() noexcept {
    static const char* const export_name = allocate_hid_d_get_attributes_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE4E6ull));
    static const char* const module_name = allocate_hid_for_get_attributes(
        reinterpret_cast<const std::uint8_t*>(0x1414DE4FAull));
    return reinterpret_cast<HidDGetAttributesFunction>(
        resolve_dynamic_import(module_name, export_name));
}


HidDGetPreparsedDataFunction resolve_hid_d_get_preparsed_data_import() noexcept {
    static const char* const export_name =
        allocate_hid_d_get_preparsed_data_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE503ull));
    static const char* const module_name = allocate_hid_for_get_preparsed_data(
        reinterpret_cast<const std::uint8_t*>(0x1414DE51Aull));
    return reinterpret_cast<HidDGetPreparsedDataFunction>(
        resolve_dynamic_import(module_name, export_name));
}


HidPGetCapsFunction resolve_hid_p_get_caps_import() noexcept {
    static const char* const export_name = allocate_hid_p_get_caps_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DE523ull));
    static const char* const module_name = allocate_hid_for_get_caps(
        reinterpret_cast<const std::uint8_t*>(0x1414DE531ull));
    return reinterpret_cast<HidPGetCapsFunction>(
        resolve_dynamic_import(module_name, export_name));
}


HidDGetProductStringFunction resolve_hid_d_get_product_string_import() noexcept {
    static const char* const export_name =
        allocate_hid_d_get_product_string_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE53Aull));
    static const char* const module_name = allocate_hid_for_get_product_string(
        reinterpret_cast<const std::uint8_t*>(0x1414DE551ull));
    return reinterpret_cast<HidDGetProductStringFunction>(
        resolve_dynamic_import(module_name, export_name));
}


HidDFreePreparsedDataFunction resolve_hid_d_free_preparsed_data_import() noexcept {
    static const char* const export_name =
        allocate_hid_d_free_preparsed_data_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DE55Aull));
    static const char* const module_name = allocate_hid_for_free_preparsed_data(
        reinterpret_cast<const std::uint8_t*>(0x1414DE572ull));
    return reinterpret_cast<HidDFreePreparsedDataFunction>(
        resolve_dynamic_import(module_name, export_name));
}


RegQueryValueExAFunction resolve_reg_query_value_ex_a_import() noexcept {
    static const char* const export_name = allocate_reg_query_value_ex_a_export_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD00Aull));
    static const char* const module_name = allocate_advapi32_for_reg_query_value_ex_a(
        reinterpret_cast<const std::uint8_t*>(0x1414DD01Cull));
    return reinterpret_cast<RegQueryValueExAFunction>(
        resolve_dynamic_import(module_name, export_name));
}


void register_create_directory_w_binding() noexcept {
    static const FARPROC binding = []() noexcept {
        static const char* const export_name = allocate_create_directory_w_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD1C8ull));
        static const char* const module_name = allocate_kernel32_for_create_directory_w(
            reinterpret_cast<const std::uint8_t*>(0x1414DD1DAull));
        const HMODULE module = LoadLibraryA(module_name);
        return module == nullptr ? nullptr : GetProcAddress(module, export_name);
    }();
    (void)binding;
}


void register_find_first_file_w_binding() noexcept {
    static const FARPROC binding = []() noexcept {
        static const char* const export_name = allocate_find_first_file_w_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD1E8ull));
        static const char* const module_name = allocate_kernel32_for_find_first_file_w(
            reinterpret_cast<const std::uint8_t*>(0x1414DD1F8ull));
        const HMODULE module = LoadLibraryA(module_name);
        return module == nullptr ? nullptr : GetProcAddress(module, export_name);
    }();
    (void)binding;
}


void register_find_next_file_w_binding() noexcept {
    static const FARPROC binding = []() noexcept {
        static const char* const export_name = allocate_find_next_file_w_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD206ull));
        static const char* const module_name = allocate_kernel32_for_find_next_file_w(
            reinterpret_cast<const std::uint8_t*>(0x1414DD215ull));
        const HMODULE module = LoadLibraryA(module_name);
        return module == nullptr ? nullptr : GetProcAddress(module, export_name);
    }();
    (void)binding;
}


void register_find_close_binding() noexcept {
    static const FARPROC binding = []() noexcept {
        static const char* const export_name = allocate_find_close_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD223ull));
        static const char* const module_name = allocate_kernel32_for_find_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DD22Eull));
        const HMODULE module = LoadLibraryA(module_name);
        return module == nullptr ? nullptr : GetProcAddress(module, export_name);
    }();
    (void)binding;
}

}
