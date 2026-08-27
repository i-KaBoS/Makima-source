#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <wbemidl.h>

namespace makima::platform::com {




[[nodiscard]] bool query_first_wmi_utf8_value(
    IWbemServices* services,
    wchar_t* query,
    wchar_t* property_name,
    char* output) noexcept;

[[nodiscard]] std::uint64_t execute_wmi_query(
    std::vector<std::string>* results,
    wchar_t* query,
    IWbemServices* services,
    wchar_t* property_name,
    const wchar_t* query_dialect = L"WQL") noexcept;
void append_power_process_network_inventory(
    std::string& json,
    IWbemServices* services);

}
