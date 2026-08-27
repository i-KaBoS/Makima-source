#include "storage/registry/registry.hpp"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cwchar>

namespace makima::storage::registry {




wchar_t* allocate_quoted_executable_and_url_argument_template(
    const std::uint16_t* protected_source);
wchar_t* allocate_loader_protocol_registry_path(std::int64_t protected_source);
wchar_t* allocate_loader_protocol_display_name(const std::uint16_t* protected_source);
wchar_t* allocate_url_protocol_registry_value_name(std::int64_t protected_source);
wchar_t* allocate_default_icon_registry_key_name(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input);
wchar_t* allocate_quoted_executable_icon_index_zero_template(
    const std::uint16_t* protected_source);
wchar_t* allocate_shell_registry_key_name(const std::uint16_t* protected_source);
wchar_t* allocate_open_registry_key_name(const std::uint16_t* protected_source);
wchar_t* allocate_command_registry_key_name(const std::uint16_t* protected_source);

namespace {

[[nodiscard]] DWORD wide_string_bytes(const wchar_t* value) noexcept {
    return static_cast<DWORD>((std::wcslen(value) + 1U) * sizeof(wchar_t));
}

}




std::uint64_t register_loader_url_protocol() noexcept {
    std::array<wchar_t, 264> executable_path{};
    if (::GetModuleFileNameW(
            nullptr,
            executable_path.data(),
            static_cast<DWORD>(MAX_PATH)) == 0) {
        return 0;
    }

    static const wchar_t* const command_line_template =
        allocate_quoted_executable_and_url_argument_template(
            reinterpret_cast<const std::uint16_t*>(0x1414D8F98ull));
    std::array<wchar_t, 276> command_line{};
    static_cast<void>(::_snwprintf_s(
        command_line.data(),
        command_line.size(),
        _TRUNCATE,
        command_line_template,
        executable_path.data()));

    static const wchar_t* const protocol_key_path =
        allocate_loader_protocol_registry_path(0x1414D8FB0ll);
    HKEY protocol_key = nullptr;
    const LSTATUS root_status = ::RegCreateKeyExW(
        HKEY_CURRENT_USER,
        protocol_key_path,
        0,
        nullptr,
        0,
        0x20006,
        nullptr,
        &protocol_key,
        nullptr);
    if (root_status != ERROR_SUCCESS) return 0;

    static const wchar_t* const display_name =
        allocate_loader_protocol_display_name(
            reinterpret_cast<const std::uint16_t*>(0x1414D8FF0ull));
    (void)::RegSetValueExW(
        protocol_key,
        nullptr,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(display_name),
        wide_string_bytes(display_name));

    static const wchar_t* const url_protocol_value_name =
        allocate_url_protocol_registry_value_name(0x1414D9024ll);
    constexpr wchar_t empty_value[] = L"";
    (void)::RegSetValueExW(
        protocol_key,
        url_protocol_value_name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(empty_value),
        sizeof(empty_value));

    static const wchar_t* const default_icon_key_name =
        allocate_default_icon_registry_key_name(0x1414D9040ll, 0);
    HKEY default_icon_key = nullptr;
    if (::RegCreateKeyExW(
            protocol_key,
            default_icon_key_name,
            0,
            nullptr,
            0,
            0x20006,
            nullptr,
            &default_icon_key,
            nullptr) == ERROR_SUCCESS) {
        static const wchar_t* const icon_template =
            allocate_quoted_executable_icon_index_zero_template(
                reinterpret_cast<const std::uint16_t*>(0x1414D905Aull));
        std::array<wchar_t, 264> icon_value{};
        static_cast<void>(::_snwprintf_s(
            icon_value.data(),
            icon_value.size(),
            _TRUNCATE,
            icon_template,
            executable_path.data()));
        (void)::RegSetValueExW(
            default_icon_key,
            nullptr,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(icon_value.data()),
            wide_string_bytes(icon_value.data()));
        (void)::RegCloseKey(default_icon_key);
    }

    static const wchar_t* const shell_key_name = allocate_shell_registry_key_name(
        reinterpret_cast<const std::uint16_t*>(0x1414D906Aull));
    HKEY shell_key = nullptr;
    if (::RegCreateKeyExW(
            protocol_key,
            shell_key_name,
            0,
            nullptr,
            0,
            0x20006,
            nullptr,
            &shell_key,
            nullptr) == ERROR_SUCCESS) {
        static const wchar_t* const open_key_name = allocate_open_registry_key_name(
            reinterpret_cast<const std::uint16_t*>(0x1414D9078ull));
        HKEY open_key = nullptr;
        if (::RegCreateKeyExW(
                shell_key,
                open_key_name,
                0,
                nullptr,
                0,
                0x20006,
                nullptr,
                &open_key,
                nullptr) == ERROR_SUCCESS) {
            static const wchar_t* const command_key_name = allocate_command_registry_key_name(
                reinterpret_cast<const std::uint16_t*>(0x1414D9084ull));
            HKEY command_key = nullptr;
            if (::RegCreateKeyExW(
                    open_key,
                    command_key_name,
                    0,
                    nullptr,
                    0,
                    0x20006,
                    nullptr,
                    &command_key,
                    nullptr) == ERROR_SUCCESS) {
                (void)::RegSetValueExW(
                    command_key,
                    nullptr,
                    0,
                    REG_SZ,
                    reinterpret_cast<const BYTE*>(command_line.data()),
                    wide_string_bytes(command_line.data()));
                (void)::RegCloseKey(command_key);
            }
            (void)::RegCloseKey(open_key);
        }
        (void)::RegCloseKey(shell_key);
    }

    (void)::RegCloseKey(protocol_key);
    return 1;
}

}
