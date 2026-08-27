#include "makima/platform/windows_management.hpp"

#include <windows.h>
#include <winsvc.h>

#include <array>
#include <system_error>

namespace makima::platform {
namespace {

class ServiceHandle final {
public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle() { if (value_ != nullptr) CloseServiceHandle(value_); }
    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;
    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }

private:
    SC_HANDLE value_{};
};

bool set_registry_string(HKEY key, const wchar_t* name, std::wstring_view value) {
    return RegSetValueExW(
        key,
        name,
        0,
        REG_SZ,
        reinterpret_cast<const BYTE*>(value.data()),
        static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t))) == ERROR_SUCCESS;
}

}

ServiceStatus query_service_status(std::wstring_view service_name) {
    if (service_name.empty()) return {};
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager) return {};
    const std::wstring name(service_name);
    ServiceHandle service{OpenServiceW(manager.get(), name.c_str(), SERVICE_QUERY_STATUS)};
    if (!service) return {};
    SERVICE_STATUS_PROCESS status{};
    DWORD written = 0;
    if (QueryServiceStatusEx(
            service.get(),
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status),
            sizeof(status),
            &written) == FALSE) {
        return {.installed = true};
    }
    return {
        .installed = true,
        .state = status.dwCurrentState,
        .process_id = status.dwProcessId,
    };
}

ServiceCleanupResult cleanup_stale_winmeminfo(bool delete_driver_file) {
    ServiceCleanupResult result;
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (manager) {
        ServiceHandle service{OpenServiceW(
            manager.get(),
            L"winmeminfo",
            SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE)};
        if (service) {
            result.service_was_present = true;
            SERVICE_STATUS_PROCESS status{};
            DWORD written = 0;
            if (QueryServiceStatusEx(
                    service.get(),
                    SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<BYTE*>(&status),
                    sizeof(status),
                    &written) != FALSE) {
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    result.service_stopped = true;
                } else {
                    SERVICE_STATUS stopped{};
                    result.service_stopped =
                        ControlService(service.get(), SERVICE_CONTROL_STOP, &stopped) != FALSE;
                }
            }
            result.service_deleted = DeleteService(service.get()) != FALSE;
        }
    }

    std::array<wchar_t, MAX_PATH> system_directory{};
    const auto length = GetSystemDirectoryW(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (length > 0 && length < system_directory.size()) {
        const auto path = std::filesystem::path{
            std::wstring_view{system_directory.data(), length}} /
            L"drivers" / L"winmeminfo.sys";
        std::error_code error;
        result.driver_file_was_present = std::filesystem::exists(path, error);
        if (delete_driver_file && result.driver_file_was_present) {
            result.driver_file_deleted = std::filesystem::remove(path, error);
        }
    }
    return result;
}

bool register_makima_url_protocol(const std::filesystem::path& executable_path) {
    if (executable_path.empty()) return false;
    constexpr wchar_t root_path[] = L"Software\\Classes\\makima-loader";
    constexpr wchar_t command_path[] =
        L"Software\\Classes\\makima-loader\\shell\\open\\command";
    HKEY root = nullptr;
    if (RegCreateKeyExW(
            HKEY_CURRENT_USER, root_path, 0, nullptr, 0, KEY_SET_VALUE,
            nullptr, &root, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const bool root_ok =
        set_registry_string(root, nullptr, L"URL:Makima Loader Protocol") &&
        set_registry_string(root, L"URL Protocol", L"");
    RegCloseKey(root);
    if (!root_ok) return false;

    HKEY command = nullptr;
    if (RegCreateKeyExW(
            HKEY_CURRENT_USER, command_path, 0, nullptr, 0, KEY_SET_VALUE,
            nullptr, &command, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const std::wstring command_line =
        L"\"" + executable_path.wstring() + L"\" \"%1\"";
    const bool command_ok = set_registry_string(command, nullptr, command_line);
    RegCloseKey(command);
    return command_ok;
}

}
