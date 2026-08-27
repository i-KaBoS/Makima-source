#include "storage/services/services.hpp"

#include <windows.h>
#include <winsvc.h>

#include <cstdint>

namespace makima::storage::services {

wchar_t* allocate_winmeminfo_service_name(const std::uint16_t* protected_source);
wchar_t* allocate_winmeminfo_driver_path(
    std::uint64_t protected_source);





void remove_winmeminfo_service_and_driver() noexcept {
    static const wchar_t* const service_name = allocate_winmeminfo_service_name(
        reinterpret_cast<const std::uint16_t*>(0x1414D9354ull));
    static const wchar_t* const driver_path =
        allocate_winmeminfo_driver_path(0x1414D936Cull);

    SC_HANDLE manager = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (manager != nullptr) {
        SC_HANDLE service = ::OpenServiceW(
            manager,
            service_name,
            DELETE | SERVICE_STOP);
        if (service != nullptr) {
            SERVICE_STATUS status{};
            (void)::ControlService(service, SERVICE_CONTROL_STOP, &status);
            (void)::DeleteService(service);
            (void)::CloseServiceHandle(service);
        }
        (void)::CloseServiceHandle(manager);
    }
    (void)::DeleteFileW(driver_path);
}

}
