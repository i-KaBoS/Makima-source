#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "storage/services/services.hpp"

#include <windows.h>

namespace makima::storage::services {

void clear_service_snapshot(ServiceSnapshot& snapshot) noexcept {
    if (!snapshot.name.empty()) {
        SecureZeroMemory(snapshot.name.data(), snapshot.name.size() * sizeof(wchar_t));
    }
    snapshot.name.clear();
    snapshot.state = 0;
    snapshot.start_type = 0;
    snapshot.present = false;
}


char* allocate_advapi32_dll(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_adjust_token_privileges(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "AdjustTokenPrivileges";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_advapi32_dll_for_adjust_token_privileges(
    const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_open_scmanager_w(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "OpenSCManagerW";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_advapi32_dll_for_open_scmanager_w(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_open_service_w(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "OpenServiceW";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_advapi32_dll_for_open_service_w(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_control_service(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "ControlService";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_advapi32_dll_for_control_service(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_close_service_handle(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "CloseServiceHandle";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_advapi32_dll_for_close_service_handle(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "advapi32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


wchar_t* allocate_winmeminfo_service_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"winmeminfo";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_winmeminfo_driver_path(std::uint64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"C:\\Windows\\System32\\drivers\\winmeminfo.sys";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


char* allocate_local_alloc_failed(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "Local alloc failed";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}

}
