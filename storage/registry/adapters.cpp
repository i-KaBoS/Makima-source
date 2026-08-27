#include "storage/registry/registry.hpp"

#include <windows.h>
#include <winhttp.h>

#include <cstdarg>
#include <array>
#include <cstring>
#include <cwchar>
#include <new>
#include <string>
#include <string_view>

namespace makima::storage::registry {

namespace {

using RegCloseKeyFunction = LSTATUS (WINAPI*)(HKEY);
using RegSetValueExWFunction = LSTATUS (WINAPI*)(
    HKEY,
    LPCWSTR,
    DWORD,
    DWORD,
    const BYTE*,
    DWORD);

RegCloseKeyFunction resolved_reg_close_key{};
RegSetValueExWFunction resolved_reg_set_value_ex_w{};




void initialize_registry_value_imports() noexcept {
    if (HMODULE const module = LoadLibraryA("advapi32.dll"); module != nullptr) {
        resolved_reg_close_key = reinterpret_cast<RegCloseKeyFunction>(
            GetProcAddress(module, "RegCloseKey"));
    }
    if (HMODULE const module = LoadLibraryA("advapi32.dll"); module != nullptr) {
        resolved_reg_set_value_ex_w = reinterpret_cast<RegSetValueExWFunction>(
            GetProcAddress(module, "RegSetValueExW"));
    }
}

[[maybe_unused]] const bool registry_value_imports_initialized = []() noexcept {
    initialize_registry_value_imports();
    return true;
}();

bool set_text_value(HKEY key, const wchar_t* name, std::wstring_view value) noexcept {
    const auto bytes = static_cast<DWORD>((value.size() + 1U) * sizeof(wchar_t));
    return resolved_reg_set_value_ex_w != nullptr && resolved_reg_set_value_ex_w(
               key,
               name,
               0,
               REG_SZ,
               reinterpret_cast<const BYTE*>(value.data()),
               bytes) == ERROR_SUCCESS;
}

}





char* allocate_get_dpi_for_monitor_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "GetDpiForMonitor";
    static_assert(sizeof(decoded_value) == 17);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}





void complete_registry_protected_boundary() noexcept {}

[[nodiscard]] char* allocate_registry_token(std::string_view value) {
    auto* output = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return output;
}



char* allocate_code_encrypt_manual_map_failed(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_registry_token("code_encrypt.manual_map_failed");
}



char* allocate_guard_shutdown_export(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_registry_token("GuardShutdown");
}



char* allocate_guard_init_exception_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_registry_token(
        R"({"check":"GuardInit raised an SEH exception"})");
}

namespace {
RegistryGuardExchange* active_guard_exchange{};
}




void initialize_registry_guard_exchange(
    RegistryGuardExchange& exchange) noexcept {
    exchange.primary.fill(std::byte{});
    exchange.ready = std::byte{};
    exchange.secondary.fill(std::byte{});
    exchange.trailer.fill(std::byte{});
    active_guard_exchange = &exchange;
}





std::uint32_t acquire_edge_update_service_lock() noexcept {
    static const wchar_t* const lock_name =
        allocate_local_edge_update_service_lock(
            reinterpret_cast<const std::uint16_t*>(0x1414D9098ull));
    HANDLE lock = CreateMutexW(
        nullptr, TRUE, lock_name);
    if (lock != nullptr && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(lock);
        return 0;
    }

    return 0x414e5501U;
}





std::uint32_t initialize_payload_http_session(HINTERNET& session) noexcept {
    if (session != nullptr) {
        return 1;
    }

    static const wchar_t* const user_agent =
        allocate_chrome_131_windows_user_agent(0x1414DB050ll);
    session = WinHttpOpen(
        user_agent,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (session == nullptr) {
        return 0;
    }

    static_cast<void>(WinHttpSetTimeouts(session, 10'000, 15'000, 30'000, 30'000));
    DWORD secure_protocols =
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
    static_assert(
        (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 |
         WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3) == 0x2800);
    static_cast<void>(WinHttpSetOption(
        session,
        WINHTTP_OPTION_SECURE_PROTOCOLS,
        &secure_protocols,
        sizeof(secure_protocols)));
    DWORD ipv6_fast_fallback = 1;
    static_cast<void>(WinHttpSetOption(
        session,
        WINHTTP_OPTION_IPV6_FAST_FALLBACK,
        &ipv6_fast_fallback,
        sizeof(ipv6_fast_fallback)));
    return 1;
}




std::int64_t format_registry_message(
    wchar_t* destination,
    const wchar_t* format,
    ...) noexcept {
    std::va_list arguments;
    va_start(arguments, format);
    const int result = vswprintf_s(destination, 0x114, format, arguments);
    va_end(arguments);
    return result;
}

bool install_protocol_handler(const ProtocolRegistration& registration) noexcept {
    if (registration.scheme.empty() || registration.command.empty()) return false;

    const std::wstring root_path = L"Software\\Classes\\" + registration.scheme;
    HKEY root = nullptr;
    if (RegCreateKeyExW(
            HKEY_CURRENT_USER,
            root_path.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_CREATE_SUB_KEY,
            nullptr,
            &root,
            nullptr) != ERROR_SUCCESS) {
        return false;
    }

    const std::wstring display = registration.display_name.empty()
        ? L"URL:" + registration.scheme + L" Protocol"
        : registration.display_name;
    const bool root_values =
        set_text_value(root, nullptr, display) && set_text_value(root, L"URL Protocol", L"");

    HKEY command = nullptr;
    const bool command_opened = RegCreateKeyExW(
        root,
        L"shell\\open\\command",
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE,
        nullptr,
        &command,
        nullptr) == ERROR_SUCCESS;
    const bool command_written =
        command_opened && set_text_value(command, nullptr, registration.command);
    if (command != nullptr && resolved_reg_close_key != nullptr) {
        resolved_reg_close_key(command);
    }
    if (resolved_reg_close_key != nullptr) resolved_reg_close_key(root);
    return root_values && command_written;
}

bool remove_protocol_handler(std::wstring_view scheme) noexcept {
    if (scheme.empty()) return false;
    const std::wstring path = L"Software\\Classes\\" + std::wstring{scheme};
    const LSTATUS status = RegDeleteTreeW(HKEY_CURRENT_USER, path.c_str());
    return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
}

}
