#include "platform/com/coordination.hpp"
#include "platform/services/calls.hpp"
#include "security/anti_analysis/anti_analysis.hpp"
#include "security/environment/environment.hpp"
#include "security/identity/identity.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <dwmapi.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include <wbemidl.h>
#include <intrin.h>
#include "../../platform/include/makima/platform/security_monitor.hpp"
#include "../../platform/include/makima/platform/system_services.hpp"

namespace makima::security::environment {

template <std::size_t Size>
[[nodiscard]] static std::unique_ptr<wchar_t[]> allocate_wmi_query_literal(
    const wchar_t (&literal)[Size]) {
    auto result = std::make_unique<wchar_t[]>(Size);
    std::copy_n(literal, Size, result.get());
    return result;
}

template <std::size_t Size>
[[nodiscard]] static std::unique_ptr<char[]> allocate_wmi_json_key_literal(
    const char (&literal)[Size]) {
    auto result = std::make_unique<char[]>(Size);
    std::copy_n(literal, Size, result.get());
    return result;
}




[[nodiscard]] static const wchar_t* baseboard_manufacturer_query() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wmi_query_literal(
        L"SELECT Manufacturer FROM Win32_BaseBoard");
    return value.get();
}



[[nodiscard]] static const wchar_t* baseboard_manufacturer_property_name() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wmi_query_literal(
        L"Manufacturer");
    return value.get();
}




[[nodiscard]] static const char* baseboard_manufacturer_json_key() {
    static const std::unique_ptr<char[]> value = allocate_wmi_json_key_literal(
        "manufacturer");
    return value.get();
}



[[nodiscard]] static const wchar_t* baseboard_serial_number_query() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wmi_query_literal(
        L"SELECT SerialNumber FROM Win32_BaseBoard");
    return value.get();
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

static std::string wmi_bstr_to_utf8(BSTR value) {
    if (value == nullptr || *value == L'\0') return {};
    const int required = WideCharToMultiByte(
        CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (required <= 1) return {};
    std::string result(static_cast<std::size_t>(required), '\0');
    WideCharToMultiByte(
        CP_UTF8, 0, value, -1, result.data(), required, nullptr, nullptr);
    result.pop_back();
    return result;
}

static std::string wmi_variant_text(const VARIANT& value) {
    return value.vt == VT_BSTR ? wmi_bstr_to_utf8(value.bstrVal) : std::string{};
}

struct FixedVolumeInventory {
    std::string letter;
    std::uint64_t total_gigabytes;
    std::uint64_t free_gigabytes;
};

struct PhysicalMemoryLiterals {
    const wchar_t* query;
    const wchar_t* dialect;
    const wchar_t* capacity_property;
    const wchar_t* speed_property;
    const wchar_t* manufacturer_property;
    const char* sticks_prefix;
    const char* comma;
    const char* object_open;
    const char* array_close;
};




static void append_physical_memory_inventory(
    std::string& json,
    IWbemServices* services,
    const PhysicalMemoryLiterals& literals) {
    json += literals.sticks_prefix;
    if (services == nullptr) {
        json += literals.array_close;
        return;
    }

    BSTR query = SysAllocString(literals.query);
    BSTR dialect = SysAllocString(literals.dialect);
    IEnumWbemClassObject* enumeration = nullptr;
    if (dialect != nullptr && query != nullptr) {
        static_cast<void>(services->ExecQuery(
            dialect,
            query,
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            &enumeration));
    }
    SysFreeString(dialect);
    SysFreeString(query);

    bool first_stick = true;
    if (enumeration != nullptr) {
        for (;;) {
            IWbemClassObject* object = nullptr;
            ULONG returned = 0;
            const HRESULT next_status = enumeration->Next(
                10'000U, 1, &object, &returned);
            if (next_status != WBEM_S_NO_ERROR || returned == 0 || object == nullptr) break;

            VARIANT capacity;
            VARIANT speed;
            VARIANT manufacturer;
            VARIANT device_locator;
            VARIANT memory_type;
            VariantInit(&capacity);
            VariantInit(&speed);
            VariantInit(&manufacturer);
            VariantInit(&device_locator);
            VariantInit(&memory_type);
            static_cast<void>(object->Get(
                literals.capacity_property, 0, &capacity, nullptr, nullptr));
            static_cast<void>(object->Get(
                literals.speed_property, 0, &speed, nullptr, nullptr));
            static_cast<void>(object->Get(
                literals.manufacturer_property, 0, &manufacturer, nullptr, nullptr));
            static const wchar_t* const device_locator_property_name =
                allocate_device_locator_property_name(
                    reinterpret_cast<const std::uint16_t*>(0x1414DD584ull));
            static_cast<void>(object->Get(
                device_locator_property_name, 0, &device_locator, nullptr, nullptr));
            static const wchar_t* const memory_type_property_name =
                allocate_memory_type_property_name(
                    reinterpret_cast<const std::uint16_t*>(0x1414DD5A2ull));
            static_cast<void>(object->Get(
                memory_type_property_name, 0, &memory_type, nullptr, nullptr));

            if (!std::exchange(first_stick, false)) json += literals.comma;
            json += literals.object_open;
            char first_property = 1;
            static const char* const capacity_megabytes_key =
                allocate_capacity_megabytes_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD5BAull));
            const std::uint64_t capacity_bytes =
                capacity.vt == VT_BSTR && capacity.bstrVal != nullptr
                ? _wcstoui64(capacity.bstrVal, nullptr, 10)
                : 0U;
            append_json_integer_property(
                &json,
                capacity_megabytes_key,
                static_cast<std::int64_t>(capacity_bytes >> 20U),
                &first_property);
            static const char* const speed_megahertz_key =
                allocate_speed_megahertz_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD5C7ull));
            const std::int64_t speed_mhz = speed.vt == VT_I4 ? speed.lVal : 0;
            append_json_integer_property(
                &json,
                speed_megahertz_key,
                speed_mhz,
                &first_property);

            std::string slot = wmi_variant_text(device_locator);
            if (slot.empty()) {
                static const char* const unknown_memory_slot =
                    allocate_unknown_memory_slot_label(
                        reinterpret_cast<const std::uint8_t*>(0x1414DD5D2ull));
                slot = unknown_memory_slot;
            }
            static const char* const memory_slot_key = allocate_memory_slot_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DD5DBull));
            append_json_string_property(
                &json, memory_slot_key, slot.c_str(), &first_property);

            std::string manufacturer_text = wmi_variant_text(manufacturer);
            if (manufacturer_text.empty()) {
                static const char* const unknown_memory_manufacturer =
                    allocate_unknown_memory_manufacturer_label(
                        reinterpret_cast<const std::uint8_t*>(0x1414DD5E1ull));
                manufacturer_text = unknown_memory_manufacturer;
            }
            static const char* const memory_manufacturer_key =
                allocate_memory_manufacturer_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD5EAull));
            append_json_string_property(
                &json,
                memory_manufacturer_key,
                manufacturer_text.c_str(),
                &first_property);

            const std::uint32_t memory_type_value = memory_type.vt == VT_I4
                ? static_cast<std::uint32_t>(memory_type.lVal)
                : 0U;
            const char* memory_type_text = nullptr;
            switch (memory_type_value) {
            case 0x14U: {
                static const char* const ddr = allocate_ddr_memory_type_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD601ull));
                memory_type_text = ddr;
                break;
            }
            case 0x15U: {
                static const char* const ddr2 = allocate_ddr2_memory_type_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD606ull));
                memory_type_text = ddr2;
                break;
            }
            case 0x18U: {
                static const char* const ddr3 = allocate_ddr3_memory_type_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD60Cull));
                memory_type_text = ddr3;
                break;
            }
            case 0x1AU: {
                static const char* const ddr4 = allocate_ddr4_memory_type_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD612ull));
                memory_type_text = ddr4;
                break;
            }
            case 0x22U: {
                static const char* const ddr5 = allocate_ddr5_memory_type_label(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD618ull));
                memory_type_text = ddr5;
                break;
            }
            default: {
                static const char* const unknown_memory_type =
                    allocate_unknown_memory_type_label(
                        reinterpret_cast<const std::uint8_t*>(0x1414DD5F8ull));
                memory_type_text = unknown_memory_type;
                break;
            }
            }
            static const char* const memory_type_key = allocate_memory_type_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DD61Eull));
            append_json_string_property(
                &json, memory_type_key, memory_type_text, &first_property);
            static const char* const memory_stick_object_close =
                allocate_memory_stick_json_object_close(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD624ull));
            json += memory_stick_object_close;

            VariantClear(&capacity);
            VariantClear(&speed);
            VariantClear(&manufacturer);
            VariantClear(&device_locator);
            VariantClear(&memory_type);
            object->Release();
        }
    }
    if (enumeration != nullptr) enumeration->Release();
    json += literals.array_close;
}

static std::optional<std::string> query_first_wmi_string(
    IWbemServices* services,
    const wchar_t* query,
    const wchar_t* property) {
    std::array<char, 0x100> value{};
    if (::makima::platform::com::query_first_wmi_utf8_value(
            services,
            const_cast<wchar_t*>(query),
            const_cast<wchar_t*>(property),
            value.data())) {
        return std::string{value.data()};
    }
    return std::nullopt;
}

static void append_runtime_analysis_indicators(
    std::vector<std::string>& indicators,
    std::span<const ::makima::platform::ProcessRecord> processes) {
    constexpr std::array<std::string_view, 5> tooling_tokens{
        "speedhack", "dbk64", "dbk32", "fiddlercore", "titanium"};
    for (const auto& process : processes) {
        std::string image = normalize_inventory_identifier(process.image_name);
        for (const auto token : tooling_tokens) {
            if (image.find(token) == std::string::npos) continue;
            indicators.emplace_back("anti_debug.tooling_process:");
            indicators.back().append(token);
        }
    }

    wchar_t key_log_path[2]{};
    if (GetEnvironmentVariableW(
            ::makima::security::anti_analysis::ssl_key_log_environment_name(),
            key_log_path,
            static_cast<DWORD>(std::size(key_log_path))) != 0) {
        indicators.emplace_back(
            ::makima::security::anti_analysis::ssl_key_log_event());
        indicators.back().push_back(':');
        indicators.back().append(
            ::makima::security::anti_analysis::ssl_key_log_detail());
    }

    LARGE_INTEGER frequency{};
    LARGE_INTEGER begin{};
    LARGE_INTEGER end{};
    if (QueryPerformanceFrequency(&frequency) && QueryPerformanceCounter(&begin)) {
        volatile std::uint32_t accumulator = 0;
        for (std::uint32_t index = 0; index != 100000; ++index) accumulator ^= index;
        QueryPerformanceCounter(&end);
        const auto elapsed_ms = frequency.QuadPart == 0
            ? 0
            : (end.QuadPart - begin.QuadPart) * 1000 / frequency.QuadPart;
        if (elapsed_ms > 50) {
            indicators.emplace_back(
                ::makima::security::anti_analysis::timing_anomaly_event());
            indicators.back().push_back(':');
            indicators.back().append(
                ::makima::security::anti_analysis::timing_anomaly_detail());
        }
        (void)accumulator;
    }

    const DWORD current_process_id = GetCurrentProcessId();
    const auto current = std::find_if(
        processes.begin(), processes.end(), [current_process_id](const auto& process) {
            return process.process_id == current_process_id;
        });
    if (current != processes.end()) {
        const auto parent = std::find_if(
            processes.begin(), processes.end(), [current](const auto& process) {
                return process.process_id == current->parent_process_id;
            });
        if (parent != processes.end()) {
            std::string parent_name = parent->image_name;
            std::transform(
                parent_name.begin(), parent_name.end(), parent_name.begin(), [](unsigned char value) {
                    return static_cast<char>(std::tolower(value));
                });
            constexpr std::array<std::string_view, 4> allowed_parents{
                "explorer.exe", "userinit.exe", "winlogon.exe", "services.exe"};
            if (std::none_of(
                    allowed_parents.begin(), allowed_parents.end(), [&parent_name](auto allowed) {
                        return parent_name == allowed;
                    })) {
                indicators.emplace_back(
                    ::makima::security::anti_analysis::bad_parent_process_event());
                indicators.back().push_back(':');
                indicators.back().append(
                    ::makima::security::anti_analysis::bad_parent_process_detail());
            }
        }
    }

}

static std::string extract_edid_monitor_serial(
    std::span<const std::uint8_t> edid,
    const char* fallback) {
    std::string serial{fallback};
    const std::size_t descriptor_limit = std::min<std::size_t>(edid.size(), 128U);
    for (std::size_t offset = 54U; offset + 18U <= descriptor_limit; offset += 18U) {
        if (edid[offset] != 0U || edid[offset + 1U] != 0U ||
            edid[offset + 2U] != 0U || edid[offset + 3U] != 0xffU) {
            continue;
        }

        serial.clear();
        for (std::size_t index = offset + 5U; index < offset + 18U; ++index) {
            const char value = static_cast<char>(edid[index]);
            if (value == '\0' || value == '\n' || value == '\r') break;
            serial.push_back(value);
        }
        while (!serial.empty() && serial.back() == ' ') serial.pop_back();
        if (serial.empty()) serial.assign(fallback);
        break;
    }
    return serial;
}

static void append_disk_drive_inventory(
    std::string& json,
    IWbemServices* services,
    std::span<const FixedVolumeInventory> volumes) {
    static const char* const storage_prefix = allocate_storage_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDAB0ull));
    static const char* const drives_prefix = allocate_storage_drives_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDABEull));
    static const wchar_t* const query = allocate_disk_drive_inventory_query(
        reinterpret_cast<const std::uint16_t*>(0x1414DDACAull));
    static const wchar_t* const dialect = allocate_disk_wql_dialect(
        reinterpret_cast<const std::uint16_t*>(0x1414DDB6Cull));
    static const char* const item_comma = allocate_disk_json_item_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DDB76ull));
    static const char* const object_open = allocate_disk_json_object_open(
        reinterpret_cast<const std::uint8_t*>(0x1414DDB79ull));
    static const wchar_t* const model_property = allocate_disk_model_property_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DDB7Cull));
    static const wchar_t* const serial_property = allocate_disk_serial_number_property_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DDB8Aull));
    static const wchar_t* const interface_property =
        allocate_disk_interface_type_property_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DDBA6ull));
    static const wchar_t* const media_property = allocate_disk_media_type_property_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DDBC4ull));
    static const wchar_t* const size_property = allocate_disk_size_property_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DDBDAull));
    static const char* const unknown_model = allocate_unknown_disk_model_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDBE6ull));
    static const char* const empty_serial = allocate_empty_disk_serial_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDBEFull));
    static const char* const unknown_interface = allocate_unknown_disk_interface_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDBF1ull));
    static const char* const unknown_media = allocate_unknown_disk_media_type_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDBFAull));
    static const char* const unknown_size = allocate_unknown_disk_size_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC03ull));
    static const char* const nvme = allocate_nvme_storage_classification(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC0Cull));
    static const char* const nvme_lowercase =
        allocate_nvme_lowercase_storage_classification(
            reinterpret_cast<const std::uint8_t*>(0x1414DDC12ull));
    static const char* const scsi_interface = allocate_scsi_disk_interface_marker(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC18ull));
    static const char* const nvme_ssd_type = allocate_nvme_ssd_storage_type(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC1Eull));
    static const char* const fixed_media = allocate_fixed_disk_media_marker(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC28ull));
    static const char* const ssd_media = allocate_ssd_disk_media_marker(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC2Full));
    static const char* const sata_ssd_type = allocate_sata_ssd_storage_type(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC34ull));
    static const char* const removable_lowercase =
        allocate_removable_disk_media_marker_lowercase(
            reinterpret_cast<const std::uint8_t*>(0x1414DDC3Eull));
    static const char* const removable_media = allocate_removable_disk_media_marker(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC49ull));
    static const char* const removable_type = allocate_removable_storage_type(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC54ull));
    static const char* const model_key = allocate_disk_model_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC64ull));
    static const char* const serial_key = allocate_disk_serial_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC6Bull));
    static const char* const interface_key = allocate_disk_interface_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC73ull));
    static const char* const type_key = allocate_disk_type_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC7Eull));
    static const char* const size_gigabytes_key = allocate_disk_size_gigabytes_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC84ull));
    static const char* const disk_object_close = allocate_disk_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC8Dull));
    static const char* const volumes_prefix = allocate_storage_volumes_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC90ull));
    static const char* const volume_comma = allocate_volume_json_item_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC9Full));
    static const char* const volume_object_open = allocate_volume_json_object_open(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCA2ull));
    static const char* const volume_letter_key = allocate_volume_letter_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCA5ull));
    static const char* const volume_total_key = allocate_volume_total_gigabytes_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCADull));
    static const char* const volume_free_key = allocate_volume_free_gigabytes_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCB7ull));
    static const char* const volume_object_close = allocate_volume_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCC0ull));
    static const char* const storage_close = allocate_storage_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCC3ull));

    json += storage_prefix;
    json += drives_prefix;

    IEnumWbemClassObject* enumeration = nullptr;
    if (services != nullptr) {
        BSTR owned_query = SysAllocString(query);
        BSTR owned_dialect = SysAllocString(dialect);
        if (owned_query != nullptr && owned_dialect != nullptr) {
            static_cast<void>(services->ExecQuery(
                owned_dialect,
                owned_query,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr,
                &enumeration));
        }
        SysFreeString(owned_dialect);
        SysFreeString(owned_query);
    }

    bool first_disk = true;
    if (enumeration != nullptr) {
        for (;;) {
            IWbemClassObject* disk = nullptr;
            ULONG returned = 0;
            const HRESULT next_status = enumeration->Next(10'000U, 1, &disk, &returned);
            if (next_status != WBEM_S_NO_ERROR || returned == 0 || disk == nullptr) break;

            VARIANT model_value;
            VARIANT serial_value;
            VARIANT interface_value;
            VARIANT media_value;
            VARIANT size_value;
            VariantInit(&model_value);
            VariantInit(&serial_value);
            VariantInit(&interface_value);
            VariantInit(&media_value);
            VariantInit(&size_value);
            static_cast<void>(disk->Get(model_property, 0, &model_value, nullptr, nullptr));
            static_cast<void>(disk->Get(serial_property, 0, &serial_value, nullptr, nullptr));
            static_cast<void>(disk->Get(interface_property, 0, &interface_value, nullptr, nullptr));
            static_cast<void>(disk->Get(media_property, 0, &media_value, nullptr, nullptr));
            static_cast<void>(disk->Get(size_property, 0, &size_value, nullptr, nullptr));

            std::string model = wmi_variant_text(model_value);
            std::string serial = wmi_variant_text(serial_value);
            std::string interface_type = wmi_variant_text(interface_value);
            std::string media_type = wmi_variant_text(media_value);
            std::string size_text = wmi_variant_text(size_value);
            if (model.empty()) model.assign(unknown_model);
            if (serial.empty()) serial.assign(empty_serial);
            if (interface_type.empty()) interface_type.assign(unknown_interface);
            if (media_type.empty()) media_type.assign(unknown_media);
            if (size_text.empty()) size_text.assign(unknown_size);

            const std::uint64_t size_bytes = _strtoui64(size_text.c_str(), nullptr, 10);
            const char* storage_type = hard_disk_classification_label();
            if (model.find(nvme) != std::string::npos ||
                model.find(nvme_lowercase) != std::string::npos ||
                interface_type.find(scsi_interface) != std::string::npos) {
                storage_type = nvme_ssd_type;
            } else if (media_type.find(fixed_media) != std::string::npos ||
                       media_type.find(ssd_media) != std::string::npos) {
                storage_type = sata_ssd_type;
            } else if (media_type.find(removable_lowercase) != std::string::npos ||
                       media_type.find(removable_media) != std::string::npos) {
                storage_type = removable_type;
            }

            if (!std::exchange(first_disk, false)) json += item_comma;
            json += object_open;
            char first_property = '\1';
            append_json_string_property(&json, model_key, model.c_str(), &first_property);
            append_json_string_property(&json, serial_key, serial.c_str(), &first_property);
            append_json_string_property(
                &json, interface_key, interface_type.c_str(), &first_property);
            append_json_string_property(&json, type_key, storage_type, &first_property);
            append_json_integer_property(
                &json,
                size_gigabytes_key,
                static_cast<std::int64_t>(size_bytes >> 30U),
                &first_property);
            json += disk_object_close;

            VariantClear(&model_value);
            VariantClear(&serial_value);
            VariantClear(&interface_value);
            VariantClear(&media_value);
            VariantClear(&size_value);
            disk->Release();
        }
        enumeration->Release();
    }

    json += volumes_prefix;
    bool first_volume = true;
    for (const FixedVolumeInventory& volume : volumes) {
        if (!std::exchange(first_volume, false)) json += volume_comma;
        json += volume_object_open;
        char first_property = '\1';
        append_json_string_property(
            &json, volume_letter_key, volume.letter.c_str(), &first_property);
        append_json_integer_property(
            &json,
            volume_total_key,
            static_cast<std::int64_t>(volume.total_gigabytes),
            &first_property);
        append_json_integer_property(
            &json,
            volume_free_key,
            static_cast<std::int64_t>(volume.free_gigabytes),
            &first_property);
        json += volume_object_close;
    }
    json += storage_close;
}

struct OperatorDelete {
    void operator()(std::byte* allocation) const noexcept {
        ::operator delete(allocation);
    }
};




static void append_hid_mouse_array_items(std::string& json) {
    GUID hid_guid{};
    const HidDGetHidGuidFunction hid_d_get_hid_guid =
        resolve_hid_d_get_hid_guid_import();
    hid_d_get_hid_guid(&hid_guid);

    const SetupDiGetClassDevsAFunction setup_di_get_class_devs_a =
        resolve_setup_di_get_class_devs_a_import();
    HDEVINFO devices = setup_di_get_class_devs_a(
        &hid_guid,
        nullptr,
        nullptr,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devices == INVALID_HANDLE_VALUE) return;

    bool first_mouse = true;
    SP_DEVICE_INTERFACE_DATA interface_data{};
    interface_data.cbSize = sizeof(interface_data);
    for (DWORD index = 0;; ++index) {
        const SetupDiEnumDeviceInterfacesFunction enum_device_interfaces =
            resolve_setup_di_enum_device_interfaces_import();
        if (!enum_device_interfaces(
                devices, nullptr, &hid_guid, index, &interface_data)) {
            break;
        }

        DWORD required_size = 0;
        const SetupDiGetDeviceInterfaceDetailAFunction get_interface_detail =
            resolve_setup_di_get_device_interface_detail_a_import();
        static_cast<void>(get_interface_detail(
            devices,
            &interface_data,
            nullptr,
            0,
            &required_size,
            nullptr));
        if (required_size == 0) continue;

        std::unique_ptr<std::byte, OperatorDelete> detail_storage{
            static_cast<std::byte*>(::operator new(required_size))};
        auto* detail = reinterpret_cast<SP_DEVICE_INTERFACE_DETAIL_DATA_A*>(
            detail_storage.get());
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A);
        if (!resolve_setup_di_get_device_interface_detail_a_import()(
                devices,
                &interface_data,
                detail,
                required_size,
                nullptr,
                nullptr)) {
            continue;
        }

        HANDLE device = resolve_create_file_a_import()(
            detail->DevicePath,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        if (device == INVALID_HANDLE_VALUE) continue;

        HIDD_ATTRIBUTES attributes{};
        attributes.Size = sizeof(attributes);
        if (!resolve_hid_d_get_attributes_import()(device, &attributes)) {
            CloseHandle(device);
            continue;
        }

        PHIDP_PREPARSED_DATA preparsed_data = nullptr;
        if (!resolve_hid_d_get_preparsed_data_import()(device, &preparsed_data)) {
            CloseHandle(device);
            continue;
        }

        HIDP_CAPS caps{};
        const NTSTATUS caps_status =
            resolve_hid_p_get_caps_import()(preparsed_data, &caps);
        if (caps_status == static_cast<NTSTATUS>(0x00110000L) &&
            caps.UsagePage == 1U && caps.Usage == 2U) {
            std::array<wchar_t, 256> product_wide{};
            static_cast<void>(resolve_hid_d_get_product_string_import()(
                device,
                product_wide.data(),
                0x200U));
            std::array<char, 256> product_utf8{};
            const int product_length = WideCharToMultiByte(
                CP_UTF8,
                0,
                product_wide.data(),
                -1,
                product_utf8.data(),
                static_cast<int>(product_utf8.size()),
                nullptr,
                nullptr);
            product_utf8.back() = '\0';
            const char* product_name = product_utf8.data();
            if (product_length <= 0 || product_utf8.front() == '\0') {
                static const char* const unknown_product_name =
                    allocate_unknown_hid_product_name(
                        reinterpret_cast<const std::uint8_t*>(0x1414DDDCEull));
                product_name = unknown_product_name;
            }

            if (!std::exchange(first_mouse, false)) {
                static const char* const mouse_item_comma =
                    allocate_hid_mouse_json_item_comma(
                        reinterpret_cast<const std::uint8_t*>(0x1414DDDC8ull));
                json += mouse_item_comma;
            }
            static const char* const mouse_object_open =
                allocate_hid_mouse_json_object_open(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDCBull));
            static const char* const mouse_name_key = allocate_hid_mouse_name_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DDDD7ull));
            static const char* const mouse_vendor_id_key =
                allocate_hid_mouse_vendor_id_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDDDull));
            static const char* const mouse_product_id_key =
                allocate_hid_mouse_product_id_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDE2ull));
            static const char* const mouse_report_size_key =
                allocate_hid_mouse_report_size_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDE7ull));
            static const char* const mouse_object_close =
                allocate_hid_mouse_json_object_close(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDF4ull));
            json += mouse_object_open;
            char first_property = '\1';
            append_json_string_property(
                &json, mouse_name_key, product_name, &first_property);
            append_json_integer_property(
                &json,
                mouse_vendor_id_key,
                static_cast<std::int64_t>(attributes.VendorID),
                &first_property);
            append_json_integer_property(
                &json,
                mouse_product_id_key,
                static_cast<std::int64_t>(attributes.ProductID),
                &first_property);
            append_json_integer_property(
                &json,
                mouse_report_size_key,
                static_cast<std::int64_t>(caps.InputReportByteLength),
                &first_property);
            json += mouse_object_close;
        }

        static_cast<void>(
            resolve_hid_d_free_preparsed_data_import()(preparsed_data));
        CloseHandle(device);
    }

    static_cast<void>(resolve_setup_di_destroy_device_info_list_import()(devices));
}

std::string collect_host_environment_inventory() {
    const CoInitializeExFunction co_initialize_ex = resolve_co_initialize_ex_import();
    const HRESULT com_status = co_initialize_ex(nullptr, COINIT_MULTITHREADED);
    const bool release_com = SUCCEEDED(com_status);
    if (release_com) {
        const CoInitializeSecurityFunction co_initialize_security =
            resolve_co_initialize_security_import();
        (void)co_initialize_security(
            nullptr,
            -1,
            nullptr,
            nullptr,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE,
            nullptr);
    }
    const ::makima::platform::WindowsEnvironmentInspector inspector;
    const auto environment = inspector.inspect();
    const auto processes = ::makima::platform::ProcessInventory{}.snapshot();
    HWND visible_window = nullptr;
    const bool visible_window_context =
        ::makima::security::identity::enumerate_windows_for_security_context(
            GetCurrentProcessId(), &visible_window);
    if (visible_window_context) RevertToSelf();
    const std::uintptr_t inventory_target = reinterpret_cast<std::uintptr_t>(
        &collect_host_environment_inventory);
    if (environment.debugger_present) {
        ::makima::telemetry::reporting::report_unauthorized_mapping(
            GetCurrentProcess(), inventory_target, inventory_target, 0, 0,
            PAGE_EXECUTE_READ, 0, GetCurrentProcessId(), GetCurrentThreadId(),
            ERROR_ACCESS_DENIED);
        ::makima::telemetry::reporting::report_executable_text_protection(
            inventory_target, &inventory_target, 0, PAGE_EXECUTE_READWRITE);
    }
    if (environment.remote_session) {
        ::makima::telemetry::reporting::report_external_thread_suspend(
            inventory_target, GetCurrentThreadId());
    }
    if (environment.hypervisor_present) {
        ::makima::telemetry::reporting::report_remote_or_executable_thread_start(
            GetCurrentProcess(), GetCurrentProcessId(), inventory_target,
            inventory_target, 0);
    }
    auto indicators = environment.virtualization_indicators;
    append_runtime_analysis_indicators(indicators, processes);

    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    const GlobalMemoryStatusExFunction global_memory_status_ex =
        resolve_global_memory_status_ex_import();
    const bool memory_available = global_memory_status_ex(&memory) != FALSE;
    SYSTEMTIME captured_at{};
    const GetSystemTimeFunction get_system_time = resolve_get_system_time_import();
    get_system_time(&captured_at);
    std::array<char, 32> captured_timestamp{};
    static const char* const timestamp_format =
        allocate_iso_8601_utc_timestamp_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DD24Bull));
    static const char* const collected_at_prefix =
        allocate_collected_at_json_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DD26Bull));
    std::snprintf(
        captured_timestamp.data(), captured_timestamp.size(),
        timestamp_format,
        captured_at.wYear, captured_at.wMonth, captured_at.wDay,
        captured_at.wHour, captured_at.wMinute, captured_at.wSecond);

    RTL_OSVERSIONINFOW os_version{};
    os_version.dwOSVersionInfoSize = sizeof(os_version);
    static const char* const ntdll_name = allocate_ntdll_module_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2BBull));
    static const char* const rtl_get_version_name =
        allocate_rtl_get_version_export_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD2C6ull));
    const GetModuleHandleAFunction get_module_handle_a =
        resolve_get_module_handle_a_import();
    const HMODULE ntdll_module = get_module_handle_a(ntdll_name);
    const RtlGetVersionFunction rtl_get_version = ntdll_module == nullptr
        ? nullptr
        : reinterpret_cast<RtlGetVersionFunction>(
            GetProcAddress(ntdll_module, rtl_get_version_name));
    const bool os_version_available = rtl_get_version != nullptr &&
        rtl_get_version(&os_version) >= 0;
    static const char* const unknown_os = allocate_unknown_os_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD324ull));
    static const char* const windows_11 = allocate_windows_11_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2DEull));
    static const char* const windows_10 = allocate_windows_10_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2EAull));
    const char* os_name = !os_version_available
        ? unknown_os
        : (os_version.dwMajorVersion >= 10 && os_version.dwBuildNumber >= 22000
            ? windows_11
            : windows_10);

    SYSTEM_INFO system_info{};
    get_system_info_binding(&system_info);
    int cpu_leaf[4]{};
    __cpuid(cpu_leaf, 1);
    const bool sse41 = (cpu_leaf[2] & (1 << 19)) != 0;
    const bool sse42 = (cpu_leaf[2] & (1 << 20)) != 0;
    const bool avx = (cpu_leaf[2] & (1 << 28)) != 0;
    __cpuidex(cpu_leaf, 7, 0);
    const bool avx2 = (cpu_leaf[1] & (1 << 5)) != 0;
    const bool avx512f = (cpu_leaf[1] & (1 << 16)) != 0;
    static const char* const x86_64_avx512 = allocate_x86_64_avx512_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3B1ull));
    static const char* const x86_64_avx2 = allocate_x86_64_avx2_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3C1ull));
    static const char* const x86_64_avx = allocate_x86_64_avx_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3CEull));
    static const char* const x86_64_sse42 = allocate_x86_64_sse42_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3DAull));
    static const char* const x86_64_sse41 = allocate_x86_64_sse41_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3E9ull));
    static const char* const x86_sse2_or_lower = allocate_x86_sse2_or_lower_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD39Cull));
    const char* architecture = avx512f
        ? x86_64_avx512
        : (avx2 ? x86_64_avx2 : (avx ? x86_64_avx : (sse42 ? x86_64_sse42 :
            (sse41 ? x86_64_sse41 :
                (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
                    ? x86_64_sse2_architecture_label() : x86_sse2_or_lower)))));
    std::array<char, 256> processor_name{};
    std::strncpy(processor_name.data(), unknown_os, processor_name.size() - 1U);
    DWORD base_mhz = 0;
    const bool base_mhz_available = query_cpu_registry_details(
        processor_name.data(), processor_name.size() - 1U, &base_mhz);

    std::vector<FixedVolumeInventory> fixed_volumes;
    const DWORD drive_mask = GetLogicalDrives();
    for (unsigned index = 0; index < 26; ++index) {
        if ((drive_mask & (1U << index)) == 0) continue;
        char root[] = {static_cast<char>('A' + index), ':', '\\', '\0'};
        if (GetDriveTypeA(root) != DRIVE_FIXED) continue;
        ULARGE_INTEGER available{}, total{}, free{};
        if (!GetDiskFreeSpaceExA(root, &available, &total, &free)) continue;
        fixed_volumes.push_back(FixedVolumeInventory{
            std::string{root},
            total.QuadPart >> 30U,
            free.QuadPart >> 30U});
    }

    static const char* const json_object_open = allocate_json_object_open(
        reinterpret_cast<const std::uint8_t*>(0x1414DD23Cull));
    static const char* const schema_one = allocate_json_schema_one_fragment(
        reinterpret_cast<const std::uint8_t*>(0x1414DD23Full));
    static const char* const os_prefix = allocate_os_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2B2ull));
    static const char* const windows_family = allocate_windows_family_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2D5ull));
    static const char* const os_name_key = allocate_os_name_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD2FDull));
    static const char* const os_build_key = allocate_os_build_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD310ull));
    static const char* const os_close = allocate_os_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DD317ull));
    static const char* const cpu_prefix = allocate_cpu_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DD31Aull));
    static const char* const cpu_name_key = allocate_cpu_name_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD382ull));
    static const char* const base_mhz_key = allocate_base_mhz_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD378ull));
    static const char* const logical_processors_key =
        allocate_logical_processors_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DD388ull));
    static const char* const cpu_arch_key = allocate_cpu_arch_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD405ull));
    static const char* const sse41_key = allocate_sse41_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD41Full));
    static const char* const sse42_key = allocate_sse42_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD426ull));
    static const char* const avx_key = allocate_avx_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD42Dull));
    static const char* const avx2_key = allocate_avx2_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD432ull));
    static const char* const avx512f_key = allocate_avx512f_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD438ull));
    static const char* const cpu_close = allocate_cpu_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DD441ull));
    static const char* const memory_prefix = allocate_memory_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DD444ull));
    static const char* const total_mb_key = allocate_total_mb_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD451ull));
    static const char* const available_mb_key = allocate_available_mb_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD45Bull));
    static const char* const load_pct_key = allocate_load_pct_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD469ull));
    static const char* const memory_sticks_prefix =
        allocate_memory_sticks_json_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DD473ull));
    static const char* const memory_sticks_close =
        allocate_memory_sticks_json_array_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DD627ull));
    static const wchar_t* const physical_memory_inventory_query =
        allocate_physical_memory_inventory_query(
            reinterpret_cast<const std::uint16_t*>(0x1414DD480ull));
    static const wchar_t* const wmi_query_dialect = allocate_wql_dialect(
        reinterpret_cast<const std::uint16_t*>(0x1414DD536ull));
    static const char* const json_comma = allocate_json_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DD540ull));
    static const char* const memory_stick_object_open =
        allocate_memory_stick_json_object_open(
            reinterpret_cast<const std::uint8_t*>(0x1414DD543ull));
    static const wchar_t* const capacity_property_name =
        allocate_capacity_property_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DD546ull));
    static const wchar_t* const speed_property_name =
        allocate_speed_property_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DD55Aull));
    static const wchar_t* const manufacturer_property_name =
        allocate_manufacturer_property_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DD568ull));
    IWbemLocator* locator = nullptr;
    IWbemServices* services = nullptr;
    IDXGIFactory1* dxgi_factory = nullptr;
    bool wmi_services_ready = false;
    const CoCreateInstanceFunction co_create_instance = resolve_co_create_instance_import();
    if (SUCCEEDED(co_create_instance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&locator))) &&
        locator != nullptr) {
        static const wchar_t* const wmi_namespace =
            allocate_wmi_root_cimv2_namespace(
                reinterpret_cast<const std::uint16_t*>(0x1414DD29Aull));
        BSTR namespace_name = SysAllocString(wmi_namespace);
        if (namespace_name != nullptr) {
            static_cast<void>(locator->ConnectServer(
                namespace_name, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &services));
            SysFreeString(namespace_name);
        }
        if (services != nullptr) {
            const CoSetProxyBlanketFunction co_set_proxy_blanket =
                resolve_co_set_proxy_blanket_import();
            wmi_services_ready = SUCCEEDED(co_set_proxy_blanket(
                services,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                nullptr,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr,
                EOAC_NONE));
        }
    }
    std::string json = json_object_open;
    json += schema_one;
    json += os_prefix;
    json += "\"family\":\"";
    json += windows_family;
    json += "\",\"";
    json += os_name_key;
    json += "\":\"";
    char subsequent_property_state = '\0';
    append_json_escape(json, os_name);
    json += "\",\"major\":" + std::to_string(os_version.dwMajorVersion);
    json += ",\"minor\":" + std::to_string(os_version.dwMinorVersion);
    json += ",\"";
    json += os_build_key;
    json += "\":" + std::to_string(os_version.dwBuildNumber);
    json += collected_at_prefix;
    json.push_back('"');
    json += captured_timestamp.data();
    json.push_back('"');
    json += os_close;
    json += cpu_prefix;
    json += "\"";
    json += cpu_name_key;
    json += "\":\"";
    append_json_escape(json, processor_name.data());
    json += "\",\"";
    json += cpu_arch_key;
    json += "\":\"";
    append_json_escape(json, architecture);
    json += "\"";
    if (base_mhz_available) {
        json += ",\"";
        json += base_mhz_key;
        json += "\":" + std::to_string(base_mhz);
    }
    json += ",\"";
    json += logical_processors_key;
    json += "\":" + std::to_string(system_info.dwNumberOfProcessors);
    json += ",\"features\":{";
    json += "\"" + std::string{sse41_key} + "\":" +
        std::string(sse41 ? "true" : "false");
    json += ",\"" + std::string{sse42_key} + "\":" +
        std::string(sse42 ? "true" : "false");
    json += ",\"" + std::string{avx_key} + "\":" +
        std::string(avx ? "true" : "false");
    json += ",\"" + std::string{avx2_key} + "\":" +
        std::string(avx2 ? "true" : "false");
    json += ",\"" + std::string{avx512f_key} + "\":" +
        std::string(avx512f ? "true" : "false") + "}";
    json += cpu_close;
    if (memory_available) {
        json += memory_prefix;
        json += "\"";
        json += total_mb_key;
        json += "\":" + std::to_string(memory.ullTotalPhys >> 20U) +
            ",\"" + std::string{available_mb_key} + "\":" +
            std::to_string(memory.ullAvailPhys >> 20U) +
            ",\"" + std::string{load_pct_key} + "\":" +
            std::to_string(memory.dwMemoryLoad);
        append_physical_memory_inventory(
            json,
            wmi_services_ready ? services : nullptr,
            PhysicalMemoryLiterals{
                physical_memory_inventory_query,
                wmi_query_dialect,
                capacity_property_name,
                speed_property_name,
                manufacturer_property_name,
                memory_sticks_prefix,
                json_comma,
                memory_stick_object_open,
                memory_sticks_close});
        static const char* const memory_section_close =
            allocate_memory_json_section_close(
                reinterpret_cast<const std::uint8_t*>(0x1414DD62Aull));
        json += memory_section_close;
    }

    static const char* const motherboard_prefix =
        allocate_motherboard_json_object_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DD62Dull));
    json += motherboard_prefix;
    char first_motherboard_property = 1;
    if (wmi_services_ready) {



        if (const auto manufacturer_value = query_first_wmi_string(
                services,
                baseboard_manufacturer_query(),
                baseboard_manufacturer_property_name())) {
            append_json_string_property(
                &json,
                baseboard_manufacturer_json_key(),
                manufacturer_value->c_str(),
                &first_motherboard_property);
        }

        static const wchar_t* const product_property_name =
            allocate_baseboard_product_property_name(
                reinterpret_cast<const std::uint16_t*>(0x1414DD6C8ull));
        static const wchar_t* const product_query = allocate_baseboard_product_query(
            reinterpret_cast<const std::uint16_t*>(0x1414DD6DAull));
        if (const auto product_value = query_first_wmi_string(
                services, product_query, product_property_name)) {
            static const char* const product_key = allocate_baseboard_product_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DD724ull));
            append_json_string_property(
                &json,
                product_key,
                product_value->c_str(),
                &first_motherboard_property);
        }

        static const wchar_t* const serial_number_property_name =
            allocate_baseboard_serial_number_property_name(
                reinterpret_cast<const std::uint16_t*>(0x1414DD72Eull));
        if (const auto serial_value = query_first_wmi_string(
                services,
                baseboard_serial_number_query(),
                serial_number_property_name)) {
            static const char* const serial_number_key =
                allocate_baseboard_serial_number_json_key(
                    reinterpret_cast<const std::uint8_t*>(0x1414DD79Eull));
            append_json_string_property(
                &json,
                serial_number_key,
                serial_value->c_str(),
                &first_motherboard_property);
        }

        static const wchar_t* const bios_version_property_name =
            allocate_bios_version_property_name(
                reinterpret_cast<const std::uint16_t*>(0x1414DD7A6ull));
        static const wchar_t* const bios_version_query = allocate_bios_version_query(
            reinterpret_cast<const std::uint16_t*>(0x1414DD7CCull));
        if (const auto bios_version_value = query_first_wmi_string(
                services, bios_version_query, bios_version_property_name)) {
            static const char* const bios_version_key = allocate_bios_version_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DD820ull));
            append_json_string_property(
                &json,
                bios_version_key,
                bios_version_value->c_str(),
                &first_motherboard_property);
        }

        static const wchar_t* const bios_date_property_name =
            allocate_bios_release_date_property_name(
                reinterpret_cast<const std::uint16_t*>(0x1414DD82Eull));
        static const wchar_t* const bios_date_query = allocate_bios_release_date_query(
            reinterpret_cast<const std::uint16_t*>(0x1414DD848ull));
        if (const auto bios_date_value = query_first_wmi_string(
                services, bios_date_query, bios_date_property_name)) {
            static const char* const bios_date_key = allocate_bios_release_date_json_key(
                reinterpret_cast<const std::uint8_t*>(0x1414DD890ull));
            append_json_string_property(
                &json,
                bios_date_key,
                bios_date_value->c_str(),
                &first_motherboard_property);
        }
    }
    static const char* const motherboard_close =
        allocate_motherboard_json_object_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DD89Bull));
    json += motherboard_close;
    append_json_boolean_property(
        &json, "debugger", environment.debugger_present, &subsequent_property_state);
    append_json_boolean_property(
        &json, "remote_session", environment.remote_session, &subsequent_property_state);
    append_json_boolean_property(
        &json, "hypervisor", environment.hypervisor_present, &subsequent_property_state);
    append_json_boolean_property(
        &json, "visible_window_context", visible_window_context, &subsequent_property_state);
    static const char* const gpus_prefix = allocate_gpus_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DD89Eull));
    json += gpus_prefix;
    static const char* const gpu_object_open = allocate_gpu_json_object_open(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8ACull));
    static const char* const gpu_name_key = allocate_gpu_name_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8AFull));
    static const char* const gpu_vendor_id_key = allocate_gpu_vendor_id_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8B5ull));
    static const char* const gpu_device_id_key = allocate_gpu_device_id_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8C0ull));
    static const char* const gpu_vram_megabytes_key =
        allocate_gpu_vram_megabytes_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DD8CBull));
    static const char* const gpu_shared_megabytes_key =
        allocate_gpu_shared_megabytes_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DD8D4ull));
    static const char* const gpu_object_close = allocate_gpu_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8DFull));
    static const char* const gpu_array_close = allocate_gpu_json_array_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DD8E2ull));

    bool first = true;
    for (const auto& adapter : environment.graphics_scheduling) {
        if (!std::exchange(first, false)) {
            static const char* const gpu_comma = allocate_gpu_json_item_comma(
                reinterpret_cast<const std::uint8_t*>(0x1414DD8A9ull));
            json += gpu_comma;
        }
        json += gpu_object_open;
        json.push_back('"');
        json += gpu_name_key;
        json += "\":";
        append_json_escaped_text(&json, adapter.adapter.c_str());
        append_json_integer_property(
            &json, gpu_vendor_id_key, 0, &subsequent_property_state);
        append_json_integer_property(
            &json, gpu_device_id_key, 0, &subsequent_property_state);
        append_json_integer_property(
            &json, gpu_vram_megabytes_key, 0, &subsequent_property_state);
        append_json_integer_property(
            &json, gpu_shared_megabytes_key, 0, &subsequent_property_state);
        append_json_boolean_property(
            &json, "query_succeeded", adapter.query_succeeded,
            &subsequent_property_state);
        append_json_boolean_property(
            &json, "hags_supported", adapter.hardware_scheduling_supported,
            &subsequent_property_state);
        append_json_boolean_property(
            &json, "hags_enabled", adapter.hardware_scheduling_enabled,
            &subsequent_property_state);
        json += gpu_object_close;
    }

    std::vector<std::byte> cache_record(0x10000);
    wchar_t cache_directory[MAX_PATH]{};
    wchar_t next_cache_name[MAX_PATH]{};
    std::uint32_t cache_bytes = 0;
    const bool cache_directory_found = locate_internet_cache_directory(
        cache_directory, std::size(cache_directory));
    format_cache_record_filename(next_cache_name, std::size(next_cache_name));
    const bool cache_read = cache_directory_found && read_first_cache_record(
        cache_directory,
        cache_record.data(),
        static_cast<std::uint32_t>(cache_record.size()),
        &cache_bytes);
    const bool cache_valid = cache_read && validate_cache_record(
        std::span<const std::byte>{cache_record}.first(cache_bytes));
    json += gpu_array_close;

    static const char* const gpu_drivers_prefix =
        allocate_gpu_drivers_json_array_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DD8E5ull));
    static const char* const graphics_registry_path =
        allocate_display_adapter_class_registry_path(
            reinterpret_cast<const std::uint8_t*>(0x1414DD8F7ull));
    static const char* const driver_description_value_name =
        allocate_driver_description_registry_value_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD946ull));
    static const char* const driver_version_value_name =
        allocate_driver_version_registry_value_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD952ull));
    static const char* const driver_date_value_name =
        allocate_driver_date_registry_value_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DD961ull));
    static const char* const driver_comma = allocate_gpu_driver_json_item_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DD96Dull));
    static const char* const driver_object_open =
        allocate_gpu_driver_json_object_open(
            reinterpret_cast<const std::uint8_t*>(0x1414DD970ull));
    static const char* const driver_description_key =
        allocate_gpu_driver_description_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DD973ull));
    static const char* const driver_version_key = allocate_gpu_driver_version_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD979ull));
    static const char* const driver_date_key = allocate_gpu_driver_date_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DD982ull));
    static const char* const driver_object_close =
        allocate_gpu_driver_json_object_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DD988ull));
    static const char* const gpu_drivers_close = allocate_gpu_drivers_json_array_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DD98Bull));

    json += gpu_drivers_prefix;
    const RegOpenKeyExAFunction reg_open_key_ex_a = resolve_reg_open_key_ex_a_import();
    const RegQueryValueExAFunction reg_query_value_ex_a =
        resolve_reg_query_value_ex_a_import();
    const RegCloseKeyFunction reg_close_key = resolve_reg_close_key_import();
    HKEY graphics_key = nullptr;
    const LSTATUS graphics_registry_status = reg_open_key_ex_a == nullptr
        ? ERROR_PROC_NOT_FOUND
        : reg_open_key_ex_a(
            HKEY_LOCAL_MACHINE, graphics_registry_path, 0, KEY_READ, &graphics_key);
    bool first_driver = true;
    if (graphics_registry_status == ERROR_SUCCESS && graphics_key != nullptr) {
        const auto query_registry_string = [reg_query_value_ex_a](
                                               HKEY key,
                                               const char* value_name) {
            std::array<char, 0x400> value{};
            DWORD value_type = 0;
            DWORD value_bytes = static_cast<DWORD>(value.size());
            if (reg_query_value_ex_a == nullptr ||
                reg_query_value_ex_a(
                    key,
                    value_name,
                    nullptr,
                    &value_type,
                    reinterpret_cast<LPBYTE>(value.data()),
                    &value_bytes) != ERROR_SUCCESS ||
                (value_type != REG_SZ && value_type != REG_EXPAND_SZ)) {
                return std::string{};
            }
            value.back() = '\0';
            return std::string{value.data()};
        };

        for (DWORD index = 0;; ++index) {
            std::array<char, 0x100> subkey_name{};
            DWORD subkey_name_capacity = static_cast<DWORD>(subkey_name.size());
            const RegEnumKeyExAFunction reg_enum_key_ex_a =
                resolve_reg_enum_key_ex_a_import();
            if (reg_enum_key_ex_a == nullptr ||
                reg_enum_key_ex_a(
                    graphics_key,
                    index,
                    subkey_name.data(),
                    &subkey_name_capacity,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr) != ERROR_SUCCESS) {
                break;
            }

            HKEY adapter_key = nullptr;
            if (reg_open_key_ex_a(
                    graphics_key,
                    subkey_name.data(),
                    0,
                    KEY_READ,
                    &adapter_key) != ERROR_SUCCESS ||
                adapter_key == nullptr) {
                continue;
            }
            const std::string description =
                query_registry_string(adapter_key, driver_description_value_name);
            const std::string version =
                query_registry_string(adapter_key, driver_version_value_name);
            const std::string date =
                query_registry_string(adapter_key, driver_date_value_name);
            if (reg_close_key != nullptr) reg_close_key(adapter_key);
            if (description.empty() && version.empty() && date.empty()) continue;

            if (!std::exchange(first_driver, false)) json += driver_comma;
            json += driver_object_open;
            char first_driver_property = '\1';
            append_json_string_property(
                &json, driver_description_key, description.c_str(), &first_driver_property);
            append_json_string_property(
                &json, driver_version_key, version.c_str(), &first_driver_property);
            append_json_string_property(
                &json, driver_date_key, date.c_str(), &first_driver_property);
            json += driver_object_close;
        }
    }
    if (graphics_key != nullptr && reg_close_key != nullptr) reg_close_key(graphics_key);
    json += gpu_drivers_close;

    static const char* const hags_prefix = allocate_hags_enabled_json_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DD98Eull));
    json += hags_prefix;
    if (!environment.graphics_scheduling.empty() &&
        environment.graphics_scheduling.front().hardware_scheduling_enabled) {
        static const char* const hags_true = allocate_json_true_for_hags(
            reinterpret_cast<const std::uint8_t*>(0x1414DD9A0ull));
        json += hags_true;
    } else {
        static const char* const hags_false = allocate_json_false_for_hags(
            reinterpret_cast<const std::uint8_t*>(0x1414DD9A6ull));
        json += hags_false;
    }

    ID3D11Device* d3d11_device = nullptr;
    ID3D11DeviceContext* d3d11_context = nullptr;
    D3D_FEATURE_LEVEL d3d11_feature_level{};
    const D3D11CreateDeviceFunction d3d11_create_device =
        resolve_d3d11_create_device_import();
    const HRESULT d3d11_status = d3d11_create_device(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr,
        0,
        D3D11_SDK_VERSION,
        &d3d11_device,
        &d3d11_feature_level,
        &d3d11_context);
    if (SUCCEEDED(d3d11_status)) {
        static const char* const unknown_feature_level =
            allocate_unknown_d3d11_feature_level_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9ADull));
        static const char* const feature_level_9_1 =
            allocate_d3d11_feature_level_9_1_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9B6ull));
        static const char* const feature_level_9_2 =
            allocate_d3d11_feature_level_9_2_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9BBull));
        static const char* const feature_level_9_3 =
            allocate_d3d11_feature_level_9_3_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9C0ull));
        static const char* const feature_level_10_0 =
            allocate_d3d11_feature_level_10_0_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9C5ull));
        static const char* const feature_level_10_1 =
            allocate_d3d11_feature_level_10_1_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9CBull));
        static const char* const feature_level_11_0 =
            allocate_d3d11_feature_level_11_0_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9D1ull));
        static const char* const feature_level_11_1 =
            allocate_d3d11_feature_level_11_1_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9D7ull));
        static const char* const feature_level_12_0 =
            allocate_d3d11_feature_level_12_0_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9DDull));
        static const char* const feature_level_12_1 =
            allocate_d3d11_feature_level_12_1_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9E3ull));
        static const char* const feature_level_12_2_or_later =
            allocate_d3d11_feature_level_12_2_or_later_label(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9E9ull));
        static const char* const feature_level_prefix =
            allocate_d3d11_feature_level_json_prefix(
                reinterpret_cast<const std::uint8_t*>(0x1414DD9F0ull));

        const char* feature_level_label = unknown_feature_level;
        switch (d3d11_feature_level) {
            case D3D_FEATURE_LEVEL_9_1:
                feature_level_label = feature_level_9_1;
                break;
            case D3D_FEATURE_LEVEL_9_2:
                feature_level_label = feature_level_9_2;
                break;
            case D3D_FEATURE_LEVEL_9_3:
                feature_level_label = feature_level_9_3;
                break;
            case D3D_FEATURE_LEVEL_10_0:
                feature_level_label = feature_level_10_0;
                break;
            case D3D_FEATURE_LEVEL_10_1:
                feature_level_label = feature_level_10_1;
                break;
            case D3D_FEATURE_LEVEL_11_0:
                feature_level_label = feature_level_11_0;
                break;
            case D3D_FEATURE_LEVEL_11_1:
                feature_level_label = feature_level_11_1;
                break;
            case D3D_FEATURE_LEVEL_12_0:
                feature_level_label = feature_level_12_0;
                break;
            case D3D_FEATURE_LEVEL_12_1:
                feature_level_label = feature_level_12_1;
                break;
            default:
                feature_level_label = feature_level_12_2_or_later;
                break;
        }
        json += feature_level_prefix;
        append_json_escaped_text(&json, feature_level_label);
        if (d3d11_context != nullptr) d3d11_context->Release();
        if (d3d11_device != nullptr) d3d11_device->Release();
        d3d11_context = nullptr;
        d3d11_device = nullptr;
    }

    static const char* const displays_prefix = allocate_displays_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA09ull));
    static const char* const display_comma = allocate_display_json_item_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA18ull));
    static const char* const display_object_open = allocate_display_json_object_open(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA1Bull));
    static const char* const display_device_key = allocate_display_device_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA1Eull));
    static const char* const display_width_key = allocate_display_width_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA26ull));
    static const char* const display_height_key = allocate_display_height_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA2Dull));
    static const char* const display_refresh_hz_key =
        allocate_display_refresh_hz_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA35ull));
    static const char* const display_bits_per_pixel_key =
        allocate_display_bits_per_pixel_json_key(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA39ull));
    static const char* const display_object_close = allocate_display_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA3Eull));
    static const char* const displays_close = allocate_displays_json_array_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA41ull));
    const EnumDisplayDevicesAFunction enum_display_devices =
        resolve_enum_display_devices_a_import();
    const EnumDisplaySettingsAFunction enum_display_settings =
        resolve_enum_display_settings_a_import();

    json += displays_prefix;
    bool first_display = true;
    if (enum_display_devices != nullptr && enum_display_settings != nullptr) {
        for (DWORD display_index = 0;; ++display_index) {
            DISPLAY_DEVICEA display_device{};
            display_device.cb = sizeof(display_device);
            if (!enum_display_devices(nullptr, display_index, &display_device, 0)) break;

            DEVMODEA display_mode{};
            display_mode.dmSize = sizeof(display_mode);
            if (!enum_display_settings(
                    display_device.DeviceName, ENUM_CURRENT_SETTINGS, &display_mode)) {
                continue;
            }

            if (!std::exchange(first_display, false)) json += display_comma;
            json += display_object_open;
            char first_display_property = '\1';
            append_json_string_property(
                &json,
                display_device_key,
                display_device.DeviceName,
                &first_display_property);
            append_json_integer_property(
                &json,
                display_width_key,
                static_cast<std::int64_t>(display_mode.dmPelsWidth),
                &first_display_property);
            append_json_integer_property(
                &json,
                display_height_key,
                static_cast<std::int64_t>(display_mode.dmPelsHeight),
                &first_display_property);
            append_json_integer_property(
                &json,
                display_refresh_hz_key,
                static_cast<std::int64_t>(display_mode.dmDisplayFrequency),
                &first_display_property);
            append_json_integer_property(
                &json,
                display_bits_per_pixel_key,
                static_cast<std::int64_t>(display_mode.dmBitsPerPel),
                &first_display_property);
            json += display_object_close;
        }
    }
    json += displays_close;

    static const char* const monitor_serials_prefix =
        allocate_monitor_serials_json_array_prefix(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA44ull));
    static const char* const empty_monitor_serials_close =
        allocate_empty_monitor_serials_json_array_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA5Aull));
    static const char* const edid_value_name = allocate_edid_registry_value_name(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA5Dull));
    static const char* const default_monitor_serial = allocate_default_monitor_serial(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA63ull));
    static const char* const monitor_serial_comma =
        allocate_monitor_serial_json_item_comma(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA72ull));
    static const char* const monitor_serial_quote_open =
        allocate_monitor_serial_json_quote_open(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA75ull));
    static const char* const monitor_serial_quote_close =
        allocate_monitor_serial_json_quote_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA78ull));
    static const char* const monitor_serials_close =
        allocate_monitor_serials_json_array_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DDA7Bull));

    json += monitor_serials_prefix;
    const SetupDiGetClassDevsAFunction setup_di_get_class_devs_a =
        resolve_setup_di_get_class_devs_a_import();
    const SetupDiEnumDeviceInfoFunction setup_di_enum_device_info =
        resolve_setup_di_enum_device_info_import();
    const SetupDiOpenDevRegKeyFunction setup_di_open_dev_reg_key =
        resolve_setup_di_open_dev_reg_key_import();
    const SetupDiDestroyDeviceInfoListFunction setup_di_destroy_device_info_list =
        resolve_setup_di_destroy_device_info_list_import();
    const RegQueryValueExAFunction monitor_reg_query_value_ex_a =
        resolve_reg_query_value_ex_a_import();
    const RegCloseKeyFunction monitor_reg_close_key = resolve_reg_close_key_import();


    constexpr GUID monitor_interface_guid{
        0xe6f07b5fU,
        0xee97U,
        0x4a90U,
        {0xb0U, 0x76U, 0x33U, 0xf5U, 0x7bU, 0xf4U, 0xeaU, 0xa7U}};
    HDEVINFO monitor_devices = INVALID_HANDLE_VALUE;
    if (setup_di_get_class_devs_a != nullptr) {
        monitor_devices = setup_di_get_class_devs_a(
            &monitor_interface_guid,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    }

    if (monitor_devices == INVALID_HANDLE_VALUE || setup_di_enum_device_info == nullptr ||
        setup_di_open_dev_reg_key == nullptr) {
        json += empty_monitor_serials_close;
        if (monitor_devices != INVALID_HANDLE_VALUE &&
            setup_di_destroy_device_info_list != nullptr) {
            setup_di_destroy_device_info_list(monitor_devices);
        }
    } else {
        bool first_monitor_serial = true;
        for (DWORD monitor_index = 0;; ++monitor_index) {
            SP_DEVINFO_DATA monitor_info{};
            monitor_info.cbSize = sizeof(monitor_info);
            if (!setup_di_enum_device_info(monitor_devices, monitor_index, &monitor_info)) break;

            HKEY monitor_key = setup_di_open_dev_reg_key(
                monitor_devices,
                &monitor_info,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DEV,
                KEY_READ);
            if (monitor_key == INVALID_HANDLE_VALUE) continue;

            std::array<std::uint8_t, 256> edid{};
            DWORD edid_size = static_cast<DWORD>(edid.size());
            DWORD edid_type = 0;
            std::string monitor_serial{default_monitor_serial};
            if (monitor_reg_query_value_ex_a != nullptr &&
                monitor_reg_query_value_ex_a(
                    monitor_key,
                    edid_value_name,
                    nullptr,
                    &edid_type,
                    edid.data(),
                    &edid_size) == ERROR_SUCCESS &&
                edid_size >= 128U) {
                monitor_serial = extract_edid_monitor_serial(
                    std::span<const std::uint8_t>{edid.data(), edid_size},
                    default_monitor_serial);
            }
            if (monitor_reg_close_key != nullptr) monitor_reg_close_key(monitor_key);

            if (!std::exchange(first_monitor_serial, false)) json += monitor_serial_comma;
            json += monitor_serial_quote_open;
            append_json_escape(json, monitor_serial);
            json += monitor_serial_quote_close;
        }
        if (setup_di_destroy_device_info_list != nullptr) {
            setup_di_destroy_device_info_list(monitor_devices);
        }
        json += monitor_serials_close;
    }

    static const char* const dwm_prefix = allocate_dwm_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA7Eull));
    static const char* const composition_key = allocate_dwm_composition_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA88ull));
    static const char* const refresh_hz_format = allocate_refresh_hz_format(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA95ull));
    static const char* const dwm_property_comma = allocate_dwm_json_property_comma(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA9Bull));
    static const char* const refresh_hz_prefix = allocate_refresh_hz_json_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDA9Eull));
    static const char* const dwm_close = allocate_dwm_json_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDAADull));

    json += dwm_prefix;
    char first_dwm_property = '\1';
    BOOL composition_enabled = FALSE;
    if (SUCCEEDED(DwmIsCompositionEnabled(&composition_enabled))) {
        append_json_boolean_property(
            &json, composition_key, composition_enabled != FALSE, &first_dwm_property);
    }
    DWM_TIMING_INFO dwm_timing{};
    dwm_timing.cbSize = sizeof(dwm_timing);
    if (SUCCEEDED(DwmGetCompositionTimingInfo(nullptr, &dwm_timing)) &&
        dwm_timing.rateRefresh.uiDenominator != 0U) {
        std::array<char, 32> refresh_hz{};
        std::snprintf(
            refresh_hz.data(),
            refresh_hz.size(),
            refresh_hz_format,
            static_cast<double>(dwm_timing.rateRefresh.uiNumerator) /
                static_cast<double>(dwm_timing.rateRefresh.uiDenominator));
        if (first_dwm_property == '\0') json += dwm_property_comma;
        first_dwm_property = '\0';
        json += refresh_hz_prefix;
        json += refresh_hz.data();
    }
    json += dwm_close;

    append_disk_drive_inventory(json, services, fixed_volumes);

    static const char* const usb_prefix = allocate_usb_json_object_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDCC7ull));
    json += usb_prefix;

    std::vector<std::string> usb_controller_devices;
    if (wmi_services_ready) {
        static const wchar_t* const usb_controller_query =
            allocate_usb_controller_device_wmi_query(
                reinterpret_cast<const std::uint16_t*>(0x1414DDCD2ull));
        static const wchar_t* const usb_controller_dialect =
            allocate_usb_controller_device_wmi_dialect(
                reinterpret_cast<const std::uint16_t*>(0x1414DDD3Eull));
        wchar_t usb_controller_name_property[] = L"Name";
        ::makima::platform::com::execute_wmi_query(
            &usb_controller_devices,
            const_cast<wchar_t*>(usb_controller_query),
            services,
            usb_controller_name_property,
            usb_controller_dialect);
    }
    static const char* const usb_device_count_key = allocate_usb_device_count_json_key(
        reinterpret_cast<const std::uint8_t*>(0x1414DDD48ull));
    json.push_back('"');
    json += usb_device_count_key;
    json += "\":";
    json += std::to_string(usb_controller_devices.size());

    static const char* const usb_hubs_prefix = allocate_usb_hubs_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDD56ull));
    json += usb_hubs_prefix;
    std::vector<std::string> usb_hubs;
    if (wmi_services_ready) {
        static const wchar_t* const usb_hub_query = allocate_usb_hub_wmi_query(
            reinterpret_cast<const std::uint16_t*>(0x1414DDD62ull));
        static const wchar_t* const usb_hub_dialect = allocate_usb_hub_wmi_dialect(
            reinterpret_cast<const std::uint16_t*>(0x1414DDDA0ull));
        static const wchar_t* const usb_hub_name_property =
            allocate_usb_hub_name_property(
                reinterpret_cast<const std::uint16_t*>(0x1414DDDAAull));
        ::makima::platform::com::execute_wmi_query(
            &usb_hubs,
            const_cast<wchar_t*>(usb_hub_query),
            services,
            const_cast<wchar_t*>(usb_hub_name_property),
            usb_hub_dialect);
    }

    for (std::size_t index = 0; index < usb_hubs.size(); ++index) {
        if (index != 0) {
            static const char* const usb_hub_comma =
                allocate_usb_hub_json_item_comma(
                    reinterpret_cast<const std::uint8_t*>(0x1414DDDB6ull));
            json += usb_hub_comma;
        }
        json.push_back('"');
        append_json_escape(json, usb_hubs[index]);
        json.push_back('"');
    }
    static const char* const usb_hubs_close = allocate_usb_hubs_array_and_object_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDDB9ull));
    json += usb_hubs_close;
    static const char* const mice_prefix = allocate_hid_mice_json_array_prefix(
        reinterpret_cast<const std::uint8_t*>(0x1414DDDBDull));
    json += mice_prefix;
    append_hid_mouse_array_items(json);
    static const char* const mice_close = allocate_hid_mice_json_array_close(
        reinterpret_cast<const std::uint8_t*>(0x1414DDDF7ull));
    json += mice_close;

    json += ",\"graphics_registry_status\":" + std::to_string(graphics_registry_status);

    std::array<char, 32> memory_pressure{};
    std::snprintf(
        memory_pressure.data(), memory_pressure.size(), "%.2f",
        static_cast<double>(memory.dwMemoryLoad));
    json += ",\"memory_pressure\":" + std::string{memory_pressure.data()};
    json += ",\"cache_record\":{";
    json += "\"directory_found\":" + std::string(cache_directory_found ? "true" : "false");
    json += ",\"bytes\":" + std::to_string(cache_bytes);
    json += ",\"valid\":" + std::string(cache_valid ? "true" : "false") + "}";
    append_json_integer_property(
        &json, "process_count", static_cast<std::int64_t>(processes.size()),
        &subsequent_property_state);
    json += ",\"indicators\":";
    append_json_array(json, indicators);

    SERVICE_STATUS_PROCESS defender_status{};
    bool defender_service_running = false;
    SC_HANDLE service_manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (service_manager != nullptr) {
        SC_HANDLE defender_service = OpenServiceW(
            service_manager, L"WinDefend", SERVICE_QUERY_STATUS);
        if (defender_service != nullptr) {
            defender_service_running =
                ::makima::platform::services::call_query_service_status_ex(
                    defender_service, defender_status) &&
                defender_status.dwCurrentState == SERVICE_RUNNING;
            CloseServiceHandle(defender_service);
        }
        CloseServiceHandle(service_manager);
    }
    append_json_string_property(
        &json, "service_manager", "Windows SCM", &subsequent_property_state);
    json += ",\"security_services\":{\"WinDefend\":";
    json += defender_service_running ? "true" : "false";
    json += ",\"pid\":" + std::to_string(defender_status.dwProcessId) + "}";

    if (wmi_services_ready) {
        ::makima::platform::com::append_power_process_network_inventory(json, services);
    }
    const CreateDxgiFactory1Function create_dxgi_factory1 =
        resolve_create_dxgi_factory1_import();
    (void)create_dxgi_factory1(
        __uuidof(IDXGIFactory1), reinterpret_cast<void**>(&dxgi_factory));
    if (services != nullptr) services->Release();
    if (locator != nullptr) locator->Release();
    if (dxgi_factory != nullptr) dxgi_factory->Release();
    if (release_com) {
        const CoUninitializeFunction co_uninitialize = resolve_co_uninitialize_import();
        co_uninitialize();
    }
    release_inventory_scratch(cache_record);
    static const char* const inventory_close =
        allocate_host_environment_json_object_close(
            reinterpret_cast<const std::uint8_t*>(0x1414DE26Aull));
    json += inventory_close;
    return json;
}

}
