#include "security/environment/environment.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
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
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include <bcrypt.h>

namespace makima::security::environment {

GetCurrentProcessFunction get_current_process_binding = nullptr;

namespace {

volatile LONG registered_callback_counter = 0;

}



void bind_get_current_process() noexcept {
    const HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    if (kernel32 != nullptr) {
        get_current_process_binding =
            reinterpret_cast<GetCurrentProcessFunction>(
                GetProcAddress(kernel32, "GetCurrentProcess"));
    }
}


char* allocate_nt_query_system_information_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtQuerySystemInformation";
    static_assert(sizeof(value) == 25U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_peb_being_debugged_detail(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"PEB.BeingDebugged set"})";
    static_assert(sizeof(value) == 34U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_flags_event(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.process_debug_flags";
    static_assert(sizeof(value) == 31U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_remote_debugger_present_event(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.remote_debugger";
    static_assert(sizeof(value) == 27U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




char* allocate_reg_close_key_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "RegCloseKey";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



char* allocate_reg_enum_key_ex_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "RegEnumKeyExA";
    static_assert(sizeof(value) == 14U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



char* allocate_advapi32_for_reg_enum_key_ex_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "advapi32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



char* allocate_d3d11_create_device_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "D3D11CreateDevice";
    static_assert(sizeof(value) == 18U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



char* allocate_d3d11_for_create_device(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "d3d11.dll";
    static_assert(sizeof(value) == 10U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}




char* allocate_find_next_file_w_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "FindNextFileW";
    static_assert(sizeof(value) == 14U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



void increment_registered_callback_counter() noexcept {
    InterlockedIncrement(&registered_callback_counter);
}


void decrement_registered_callback_counter() noexcept {
    InterlockedDecrement(&registered_callback_counter);
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



void format_cache_record_filename(
    wchar_t* destination,
    std::size_t destination_capacity) noexcept {
    if (destination == nullptr || destination_capacity == 0) return;
    destination[0] = L'\0';
    std::array<std::uint8_t, 8> identifier{};
    if (BCryptGenRandom(
            nullptr,
            identifier.data(),
            static_cast<ULONG>(identifier.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
        return;
    }
    static const wchar_t* const format = allocate_cache_record_filename_format(
        reinterpret_cast<const std::uint16_t*>(0x1414DD0ECull));
    _snwprintf_s(
        destination,
        destination_capacity,
        _TRUNCATE,
        format,
        identifier[0], identifier[1], identifier[2], identifier[3],
        identifier[4], identifier[5], identifier[6], identifier[7]);
}



const char* virtualbox_hypervisor_signature() noexcept {
    static const char* const value = allocate_virtualbox_hypervisor_signature(
        reinterpret_cast<const std::uint8_t*>(0x1414DCBA3ull));
    return value;
}

const char* parallels_hypervisor_signature() noexcept {
    static const char* const value = allocate_parallels_hypervisor_signature(
        reinterpret_cast<const std::uint8_t*>(0x1414DCBADull));
    return value;
}

const char* bhyve_hypervisor_signature() noexcept {
    static const char* const value = allocate_bhyve_hypervisor_signature(
        reinterpret_cast<const std::uint8_t*>(0x1414DCBB3ull));
    return value;
}

const char* qemu_hypervisor_signature() noexcept {
    static const char* const value = allocate_qemu_hypervisor_signature(
        reinterpret_cast<const std::uint8_t*>(0x1414DCC62ull));
    return value;
}



const char* x86_64_sse2_architecture_label() noexcept {
    static const char* const value = allocate_x86_64_sse2_architecture_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DD3F8ull));
    return value;
}



const char* hard_disk_classification_label() noexcept {
    static const char* const value = allocate_hard_disk_classification_label(
        reinterpret_cast<const std::uint8_t*>(0x1414DDC5Full));
    return value;
}

}
