#include "platform/com/coordination.hpp"
#include "security/environment/environment.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tlhelp32.h>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include <wbemidl.h>

namespace makima::platform::com {

extern "C" NTSTATUS NTAPI NtQueryTimerResolution(
    PULONG minimum_resolution,
    PULONG maximum_resolution,
    PULONG current_resolution);

template <std::size_t Size>
[[nodiscard]] static std::unique_ptr<wchar_t[]> allocate_wmi_query_literal(
    const wchar_t (&literal)[Size]) {
    auto result = std::make_unique<wchar_t[]>(Size);
    std::copy_n(literal, Size, result.get());
    return result;
}




[[nodiscard]] static wchar_t* antivirus_product_query() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wmi_query_literal(
        L"SELECT displayName, productState FROM AntiVirusProduct");
    return value.get();
}



[[nodiscard]] static wchar_t* allocate_first_wmi_query_dialect(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"WQL";
    static_assert(sizeof(value) == 8U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

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

static void append_json_array(std::string& output, std::span<const std::string> values) {
    output.push_back('[');
    bool first = true;
    for (const auto& value : values) {
        if (!std::exchange(first, false)) output.push_back(',');
        output.push_back('"'); append_json_escape(output, value); output.push_back('"');
    }
    output.push_back(']');
}

static std::string wide_to_utf8(std::wstring_view value) {
    if (value.empty()) return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (required <= 0) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), required, nullptr, nullptr);
    return result;
}

bool query_first_wmi_utf8_value(
    IWbemServices* services,
    wchar_t* query,
    wchar_t* property_name,
    char* output) noexcept {
    if (output != nullptr) output[0] = '\0';

    BSTR query_text = SysAllocString(query);
    static const wchar_t* const dialect_value =
        allocate_first_wmi_query_dialect(
            reinterpret_cast<const std::uint16_t*>(0x1414DD640ull));
    BSTR query_dialect = SysAllocString(dialect_value);
    IEnumWbemClassObject* enumeration = nullptr;
    static_cast<void>(services->ExecQuery(
        query_dialect,
        query_text,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumeration));
    SysFreeString(query_dialect);
    SysFreeString(query_text);
    if (enumeration == nullptr) return false;

    IWbemClassObject* object = nullptr;
    ULONG returned = 0;
    const HRESULT next_status = enumeration->Next(10000, 1, &object, &returned);
    if (next_status != WBEM_S_NO_ERROR) {
        enumeration->Release();
        return false;
    }

    VARIANT value;
    VariantInit(&value);
    const HRESULT property_status =
        object->Get(property_name, 0, &value, nullptr, nullptr);
    const bool has_text = SUCCEEDED(property_status) && value.vt == VT_BSTR;
    if (has_text && output != nullptr && value.bstrVal != nullptr) {
        static_cast<void>(WideCharToMultiByte(
            CP_UTF8,
            0,
            value.bstrVal,
            -1,
            output,
            0x100,
            nullptr,
            nullptr));
        output[0xff] = '\0';
    }
    VariantClear(&value);
    object->Release();
    enumeration->Release();
    return has_text;
}

std::uint64_t execute_wmi_query(
    std::vector<std::string>* results,
    wchar_t* query,
    IWbemServices* services,
    wchar_t* property_name,
    const wchar_t* query_dialect) noexcept {
    if (results == nullptr || query == nullptr || services == nullptr || property_name == nullptr) return 0;

    BSTR dialect = SysAllocString(query_dialect);
    BSTR query_text = SysAllocString(query);
    if (dialect == nullptr || query_text == nullptr) {
        SysFreeString(query_text);
        SysFreeString(dialect);
        return 0;
    }

    IEnumWbemClassObject* enumeration = nullptr;
    const HRESULT query_status = services->ExecQuery(
        dialect,
        query_text,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumeration);
    SysFreeString(query_text);
    SysFreeString(dialect);
    if (FAILED(query_status) || enumeration == nullptr) return 0;

    for (;;) {
        IWbemClassObject* object = nullptr;
        ULONG returned = 0;
        const HRESULT next_status = enumeration->Next(WBEM_INFINITE, 1, &object, &returned);
        if (FAILED(next_status) || returned == 0 || object == nullptr) break;

        VARIANT value;
        VariantInit(&value);
        if (SUCCEEDED(object->Get(property_name, 0, &value, nullptr, nullptr)) &&
            value.vt == VT_BSTR && value.bstrVal != nullptr) {
            results->push_back(wide_to_utf8(value.bstrVal));
        }
        VariantClear(&value);
        object->Release();
    }
    enumeration->Release();
    return 1;
}

struct AntivirusProductRecord {
    std::string name;
    bool enabled{};
};

static std::vector<AntivirusProductRecord> query_antivirus_products(
    IWbemServices* services) {
    std::vector<AntivirusProductRecord> products;
    if (services == nullptr) return products;

    using namespace ::makima::security::environment;
    static const wchar_t* const query_dialect = allocate_antivirus_wmi_query_dialect(
        reinterpret_cast<const std::uint16_t*>(0x1414DDF9Eull));

    BSTR dialect = SysAllocString(query_dialect);
    BSTR query = SysAllocString(antivirus_product_query());
    if (dialect == nullptr || query == nullptr) {
        SysFreeString(query);
        SysFreeString(dialect);
        return products;
    }

    IEnumWbemClassObject* enumeration = nullptr;
    const HRESULT query_status = services->ExecQuery(
        dialect,
        query,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &enumeration);
    SysFreeString(query);
    SysFreeString(dialect);
    if (FAILED(query_status) || enumeration == nullptr) return products;

    static const wchar_t* const display_name_property =
        allocate_antivirus_display_name_property(
            reinterpret_cast<const std::uint16_t*>(0x1414DDFA8ull));
    static const wchar_t* const product_state_property =
        allocate_antivirus_product_state_property(
            reinterpret_cast<const std::uint16_t*>(0x1414DDFC2ull));

    for (;;) {
        IWbemClassObject* object = nullptr;
        ULONG returned = 0;
        if (enumeration->Next(10000, 1, &object, &returned) != WBEM_S_NO_ERROR ||
            object == nullptr) {
            break;
        }

        VARIANT display_name;
        VARIANT product_state;
        VariantInit(&display_name);
        VariantInit(&product_state);
        static_cast<void>(object->Get(
            display_name_property, 0, &display_name, nullptr, nullptr));
        static_cast<void>(object->Get(
            product_state_property, 0, &product_state, nullptr, nullptr));

        AntivirusProductRecord product;
        if (display_name.vt == VT_BSTR && display_name.bstrVal != nullptr) {
            product.name = wide_to_utf8(display_name.bstrVal);
        } else {
            static const char* const unknown_product_name =
                allocate_unknown_antivirus_product_name(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDFDEull));
            product.name = unknown_product_name;
        }
        product.enabled = product_state.vt == VT_I4 &&
            (static_cast<std::uint32_t>(product_state.lVal) & 0x1000U) != 0U;
        products.push_back(std::move(product));

        VariantClear(&product_state);
        VariantClear(&display_name);
        object->Release();
    }
    enumeration->Release();
    return products;
}

void append_power_process_network_inventory(std::string& json, IWbemServices* services) {
    using namespace ::makima::security::environment;

    static const char* const power_prefix = allocate_power_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDDFAull));
    json += power_prefix;
    std::vector<std::string> power_plans;
    wchar_t power_query[] = L"SELECT ElementName FROM Win32_PowerPlan WHERE IsActive = TRUE";
    wchar_t power_property[] = L"ElementName";
    execute_wmi_query(&power_plans, power_query, services, power_property);

    static const char* const custom_plan = allocate_custom_power_plan_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDE06ull));
    static const char* const power_plan_key = allocate_power_plan_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDE4Dull));
    static const char* const power_close = allocate_power_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDE53ull));

    const char* selected_power_plan = custom_plan;
    if (!power_plans.empty()) {
        if (power_plans.front() == "High Performance") {
            static const char* const high_performance_plan =
                allocate_high_performance_power_plan_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDE0Eull));
            selected_power_plan = high_performance_plan;
        } else if (power_plans.front() == "Balanced") {
            static const char* const balanced_plan = allocate_balanced_power_plan_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DDE20ull));
            selected_power_plan = balanced_plan;
        } else if (power_plans.front() == "Power Saver") {
            static const char* const power_saver_plan = allocate_power_saver_plan_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DDE2Aull));
            selected_power_plan = power_saver_plan;
        } else if (power_plans.front() == "Ultimate Performance") {
            static const char* const ultimate_performance_plan =
                allocate_ultimate_performance_power_plan_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDE37ull));
            selected_power_plan = ultimate_performance_plan;
        }
    }
    json.push_back('"');
    json += power_plan_key;
    json += "\":\"";
    append_json_escape(json, selected_power_plan);
    json.push_back('"');
    json += power_close;

    ULONG minimum_resolution = 0;
    ULONG maximum_resolution = 0;
    ULONG current_resolution = 0;
    static const char* const timer_prefix = allocate_timer_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDE56ull));
    static const char* const ntdll_name = allocate_ntdll_for_query_timer_resolution(
        reinterpret_cast<const std::uint8_t*>(0x1414DDE62ull));
    static const char* const timer_export_name =
        allocate_nt_query_timer_resolution_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DDE6Dull));
    using QueryTimerResolutionFunction = NTSTATUS (NTAPI*)(PULONG, PULONG, PULONG);
    const auto query_timer_resolution = reinterpret_cast<QueryTimerResolutionFunction>(
        GetProcAddress(GetModuleHandleA(ntdll_name), timer_export_name));
    const NTSTATUS timer_status = query_timer_resolution == nullptr
        ? static_cast<NTSTATUS>(0xC0000139L)
        : query_timer_resolution(
              &minimum_resolution, &maximum_resolution, &current_resolution);
    static const char* const minimum_prefix =
        allocate_timer_minimum_milliseconds_json_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DDEA0ull));
    json += timer_prefix;
    json += "\"api\":\"NtQueryTimerResolution\"";
    json += minimum_prefix;
    std::array<char, 32> minimum_ms{};
    std::array<char, 32> current_ms{};
    std::array<char, 32> maximum_ms{};
    if (timer_status >= 0) {
        static const char* const current_format =
            allocate_timer_current_resolution_format(
                reinterpret_cast<const std::uint8_t*>(0x1414DDE85ull));
        static const char* const current_prefix =
            allocate_timer_current_milliseconds_json_prefix(
                reinterpret_cast<const std::uint8_t*>(0x1414DDE8Bull));
        static const char* const minimum_format =
            allocate_timer_minimum_resolution_format(
                reinterpret_cast<const std::uint8_t*>(0x1414DDE9Aull));
        static const char* const maximum_format =
            allocate_timer_maximum_resolution_format(
                reinterpret_cast<const std::uint8_t*>(0x1414DDEACull));
        static const char* const maximum_prefix =
            allocate_timer_maximum_milliseconds_json_prefix(
                reinterpret_cast<const std::uint8_t*>(0x1414DDEB2ull));
        std::snprintf(
            minimum_ms.data(), minimum_ms.size(), minimum_format,
            static_cast<double>(minimum_resolution) / 10000.0);
        std::snprintf(
            current_ms.data(), current_ms.size(), current_format,
            static_cast<double>(current_resolution) / 10000.0);
        std::snprintf(
            maximum_ms.data(), maximum_ms.size(), maximum_format,
            static_cast<double>(maximum_resolution) / 10000.0);
        json += minimum_ms.data();
        json.push_back(',');
        json += current_prefix;
        json += current_ms.data();
        json += maximum_prefix;
        json += maximum_ms.data();
    } else {
        json.push_back('0');
    }
    json += ",\"status\":" + std::to_string(timer_status);
    static const char* const timer_close = allocate_timer_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDEBEull));
    json += timer_close;

    static const char* const processes_prefix = allocate_processes_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDEC1ull));
    json += processes_prefix;
    bool process_property_written = false;
    HANDLE process_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (process_snapshot != INVALID_HANDLE_VALUE) {
        std::uint32_t process_count = 0;
        PROCESSENTRY32W process_entry{};
        process_entry.dwSize = sizeof(process_entry);
        if (Process32FirstW(process_snapshot, &process_entry)) {
            do {
                ++process_count;
            } while (Process32NextW(process_snapshot, &process_entry));
        }
        CloseHandle(process_snapshot);
        static const char* const process_count_key = allocate_process_count_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DDED1ull));
        json.push_back('"');
        json += process_count_key;
        json += "\":" + std::to_string(process_count);
        process_property_written = true;
    }
    HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (thread_snapshot != INVALID_HANDLE_VALUE) {
        std::uint32_t thread_count = 0;
        THREADENTRY32 thread_entry{};
        thread_entry.dwSize = sizeof(thread_entry);
        if (Thread32First(thread_snapshot, &thread_entry)) {
            do {
                ++thread_count;
            } while (Thread32Next(thread_snapshot, &thread_entry));
        }
        CloseHandle(thread_snapshot);
        static const char* const thread_count_key = allocate_thread_count_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DDEE0ull));
        if (process_property_written) json.push_back(',');
        json.push_back('"');
        json += thread_count_key;
        json += "\":" + std::to_string(thread_count);
    }
    static const char* const processes_close = allocate_processes_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDEEEull));
    json += processes_close;

    static const char* const antivirus_prefix = allocate_antivirus_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDEF1ull));
    json += antivirus_prefix;
    IWbemLocator* security_locator = nullptr;
    IWbemServices* security_services = nullptr;
    if (SUCCEEDED(CoCreateInstance(
            CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
            reinterpret_cast<void**>(&security_locator))) && security_locator != nullptr) {
        static const wchar_t* const security_center_namespace =
            allocate_security_center2_wmi_namespace(
                reinterpret_cast<const std::uint16_t*>(0x1414DDF02ull));
        BSTR security_namespace = SysAllocString(security_center_namespace);
        if (security_namespace != nullptr) {
            security_locator->ConnectServer(
                security_namespace, nullptr, nullptr, nullptr, 0, nullptr, nullptr,
                &security_services);
            SysFreeString(security_namespace);
        }
    }
    std::vector<AntivirusProductRecord> security_products;
    if (security_services != nullptr && SUCCEEDED(CoSetProxyBlanket(
            security_services, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE))) {


        security_products = query_antivirus_products(security_services);
    }
    if (security_services != nullptr) security_services->Release();
    if (security_locator != nullptr) security_locator->Release();

    for (std::size_t index = 0; index < security_products.size(); ++index) {
        if (index != 0) {
            static const char* const antivirus_comma =
                allocate_antivirus_json_item_comma(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDFE7ull));
            json += antivirus_comma;
        }
        static const char* const antivirus_name_key = allocate_antivirus_name_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DDFEDull));
        static const char* const antivirus_enabled_key =
            allocate_antivirus_enabled_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DDFF3ull));
        static const char* const antivirus_object_open =
            allocate_antivirus_json_object_open(
                reinterpret_cast<const std::uint8_t*>(0x1414DDFEAull));
        static const char* const antivirus_object_close =
            allocate_antivirus_json_object_close(
                reinterpret_cast<const std::uint8_t*>(0x1414DDFFCull));
        json += antivirus_object_open;
        json.push_back('"');
        json += antivirus_name_key;
        json += "\":\"";
        append_json_escape(json, security_products[index].name);
        json += "\",\"";
        json += antivirus_enabled_key;
        json += "\":";
        json += security_products[index].enabled ? "true" : "false";
        json += antivirus_object_close;
    }
    static const char* const antivirus_close = allocate_antivirus_json_array_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDFFFull));
    json += antivirus_close;

    static const char* const game_prefix = allocate_game_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DE002ull));
    json += game_prefix;
    bool game_field_written = false;
    DWORD game_mode = 0;
    DWORD auto_game_mode_enabled = 0;
    DWORD game_dvr = 0;
    DWORD fse_behavior = 0;
    static const char* const game_bar_subkey = allocate_game_bar_registry_subkey(
        reinterpret_cast<const std::uint8_t*>(0x1414DE00Dull));
    HKEY game_bar_key = nullptr;
    if (RegOpenKeyExA(
            HKEY_CURRENT_USER, game_bar_subkey, 0, KEY_READ,
            &game_bar_key) == ERROR_SUCCESS) {
        static const char* const allow_auto_game_mode_value =
            allocate_allow_auto_game_mode_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE029ull));
        DWORD value_size = sizeof(game_mode);
        if (RegQueryValueExA(
                game_bar_key, allow_auto_game_mode_value, nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&game_mode), &value_size) ==
            ERROR_SUCCESS) {
            static const char* const game_mode_key = allocate_game_mode_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE03Cull));
            json.push_back('"');
            json += game_mode_key;
            json += "\":" + std::string(game_mode != 0 ? "true" : "false");
            game_field_written = true;
        }
        static const char* const auto_game_mode_enabled_value =
            allocate_auto_game_mode_enabled_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE047ull));
        value_size = sizeof(auto_game_mode_enabled);
        if (RegQueryValueExA(
                game_bar_key, auto_game_mode_enabled_value, nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&auto_game_mode_enabled), &value_size) ==
            ERROR_SUCCESS) {
            if (game_field_written) json.push_back(',');
            static const char* const auto_game_mode_key =
                allocate_auto_game_mode_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DE05Cull));
            json.push_back('"');
            json += auto_game_mode_key;
            json += "\":";
            json += auto_game_mode_enabled != 0 ? "true" : "false";
            game_field_written = true;
        }
        RegCloseKey(game_bar_key);
    }
    static const char* const game_config_store_subkey =
        allocate_game_config_store_registry_subkey(
            reinterpret_cast<const std::uint8_t*>(0x1414DE06Cull));
    HKEY game_config_store_key = nullptr;
    if (RegOpenKeyExA(
            HKEY_CURRENT_USER, game_config_store_subkey, 0, KEY_READ,
            &game_config_store_key) == ERROR_SUCCESS) {
        static const char* const game_dvr_enabled_value =
            allocate_game_dvr_enabled_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE084ull));
        DWORD value_size = sizeof(game_dvr);
        if (RegQueryValueExA(
                game_config_store_key, game_dvr_enabled_value, nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&game_dvr), &value_size) ==
            ERROR_SUCCESS) {
            static const char* const game_dvr_key = allocate_game_dvr_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE095ull));
            if (game_field_written) json.push_back(',');
            json.push_back('"');
            json += game_dvr_key;
            json += "\":" + std::string(game_dvr != 0 ? "true" : "false");
            game_field_written = true;
        }
        static const char* const game_dvr_fse_behavior_mode_value =
            allocate_game_dvr_fse_behavior_mode_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE09Full));
        value_size = sizeof(fse_behavior);
        if (RegQueryValueExA(
                game_config_store_key, game_dvr_fse_behavior_mode_value, nullptr,
                nullptr, reinterpret_cast<LPBYTE>(&fse_behavior), &value_size) ==
            ERROR_SUCCESS) {
            static const char* const fse_behavior_mode_key =
                allocate_fse_behavior_mode_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DE0B8ull));
            if (game_field_written) json.push_back(',');
            json.push_back('"');
            json += fse_behavior_mode_key;
            json += "\":" + std::to_string(fse_behavior);
            game_field_written = true;
        }
        RegCloseKey(game_config_store_key);
    }
    static const char* const game_close = allocate_game_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DE0CBull));
    json += game_close;

    const unsigned long long elapsed_seconds =
        static_cast<unsigned long long>(GetTickCount64() / 1000ULL);
    static const char* const uptime_prefix =
        allocate_uptime_seconds_json_field_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DE0CEull));
    json += uptime_prefix;
    static const char* const unsigned_long_long_format =
        allocate_unsigned_long_long_decimal_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DE0E2ull));
    std::array<char, 32> uptime_seconds{};
    std::snprintf(
        uptime_seconds.data(), uptime_seconds.size(), unsigned_long_long_format,
        elapsed_seconds);
    json += uptime_seconds.data();

    static const char* const pagefile_prefix = allocate_pagefile_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DE0E8ull));
    json += pagefile_prefix;
    MEMORYSTATUSEX virtual_memory{};
    virtual_memory.dwLength = sizeof(virtual_memory);
    if (GlobalMemoryStatusEx(&virtual_memory) != FALSE) {
        static const char* const pagefile_total_key =
            allocate_pagefile_total_mb_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE0F7ull));
        json.push_back('"');
        json += pagefile_total_key;
        json += "\":" + std::to_string(virtual_memory.ullTotalPageFile >> 20U);
        static const char* const pagefile_available_key =
            allocate_pagefile_available_mb_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE101ull));
        json += ",\"";
        json += pagefile_available_key;
        json += "\":" + std::to_string(virtual_memory.ullAvailPageFile >> 20U);
        static const char* const total_virtual_key =
            allocate_pagefile_total_virtual_mb_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE10Full));
        json += ",\"";
        json += total_virtual_key;
        json += "\":" + std::to_string(virtual_memory.ullTotalVirtual >> 20U);
        static const char* const avail_virtual_key =
            allocate_pagefile_avail_virtual_mb_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE121ull));
        json += ",\"";
        json += avail_virtual_key;
        json += "\":" + std::to_string(virtual_memory.ullAvailVirtual >> 20U);
    }
    static const char* const pagefile_close = allocate_pagefile_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DE133ull));
    json += pagefile_close;

    static const char* const network_prefix = allocate_network_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DE136ull));
    json += network_prefix;
    static const char* const tcpip_parameters_subkey =
        allocate_tcpip_parameters_registry_subkey(
            reinterpret_cast<const std::uint8_t*>(0x1414DE144ull));
    std::array<char, 256> hostname{};
    HKEY tcpip_parameters = nullptr;
    const LSTATUS tcpip_registry_status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE, tcpip_parameters_subkey, 0, KEY_READ,
        &tcpip_parameters);
    if (tcpip_registry_status == ERROR_SUCCESS && tcpip_parameters != nullptr) {
        static const char* const hostname_registry_value =
            allocate_hostname_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE178ull));
        DWORD value_size = static_cast<DWORD>(hostname.size());
        if (RegQueryValueExA(
                tcpip_parameters, hostname_registry_value, nullptr, nullptr,
                reinterpret_cast<LPBYTE>(hostname.data()), &value_size) ==
            ERROR_SUCCESS) {
            static const char* const hostname_key = allocate_hostname_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DE182ull));
            hostname.back() = '\0';
            json.push_back('"');
            json += hostname_key;
            json += "\":\"";
            append_json_escape(json, hostname.data());
            json.push_back('"');
        }
    }
    if (tcpip_parameters != nullptr) RegCloseKey(tcpip_parameters);
    static const char* const network_close = allocate_network_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DE18Cull));
    json += network_close;

    static const char* const firmware_prefix =
        allocate_firmware_json_object_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DE18Full));
    json += firmware_prefix;
    static const char* const firmware_zero_guid =
        allocate_firmware_environment_zero_vendor_guid(
            reinterpret_cast<const std::uint8_t*>(0x1414DE19Eull));
    static_cast<void>(GetFirmwareEnvironmentVariableA(
        "", firmware_zero_guid, nullptr, 0));
    const bool legacy_bios = GetLastError() == ERROR_INVALID_FUNCTION;
    const char* boot_mode = nullptr;
    if (legacy_bios) {
        static const char* const legacy_bios_mode = allocate_legacy_bios_boot_mode(
            reinterpret_cast<const std::uint8_t*>(0x1414DE1C6ull));
        boot_mode = legacy_bios_mode;
    } else {
        static const char* const uefi_mode = allocate_uefi_boot_mode(
            reinterpret_cast<const std::uint8_t*>(0x1414DE1D3ull));
        boot_mode = uefi_mode;
    }
    static const char* const boot_mode_key = allocate_boot_mode_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DE1D9ull));
    json.push_back('"');
    json += boot_mode_key;
    json += "\":\"";
    append_json_escape(json, boot_mode);
    json.push_back('"');

    DWORD secure_boot = 0;
    static const char* const secure_boot_state_subkey =
        allocate_secure_boot_state_registry_subkey(
            reinterpret_cast<const std::uint8_t*>(0x1414DE1E4ull));
    HKEY secure_boot_state = nullptr;
    if (RegOpenKeyExA(
            HKEY_LOCAL_MACHINE, secure_boot_state_subkey, 0, KEY_READ,
            &secure_boot_state) == ERROR_SUCCESS) {
        static const char* const secure_boot_enabled_value =
            allocate_uefi_secure_boot_enabled_registry_value(
                reinterpret_cast<const std::uint8_t*>(0x1414DE217ull));
        DWORD value_size = sizeof(secure_boot);
        if (RegQueryValueExA(
                secure_boot_state, secure_boot_enabled_value, nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&secure_boot), &value_size) ==
            ERROR_SUCCESS) {
            static const char* const secure_boot_key =
                allocate_secure_boot_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DE22Eull));
            json += ",\"";
            json += secure_boot_key;
            json += "\":";
            json += secure_boot != 0 ? "true" : "false";
        }
        RegCloseKey(secure_boot_state);
    }
    static const char* const tpm_service_subkey =
        allocate_tpm_service_registry_subkey(
            reinterpret_cast<const std::uint8_t*>(0x1414DE23Bull));
    HKEY tpm_service = nullptr;
    const LSTATUS tpm_status = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE, tpm_service_subkey, 0, KEY_READ, &tpm_service);
    if (tpm_service != nullptr) RegCloseKey(tpm_service);
    static const char* const tpm_key = allocate_tpm_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DE262ull));
    json += ",\"";
    json += tpm_key;
    json += "\":";
    json += tpm_status == ERROR_SUCCESS ? "true" : "false";
    static const char* const firmware_close = allocate_firmware_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DE267ull));
    json += firmware_close;
}

}
