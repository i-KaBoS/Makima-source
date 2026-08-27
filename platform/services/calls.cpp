#include "platform/services/calls.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
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

namespace makima::kernel::symbols {
wchar_t* allocate_services_active_database_name(std::int64_t input);
}

namespace makima::platform::services {

bool call_query_service_status_ex(SC_HANDLE service, SERVICE_STATUS_PROCESS& status) {
    DWORD required = 0; return QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &required) != FALSE;
}




bool query_service_process_id(
    const wchar_t* service_name,
    std::uint32_t* process_id) noexcept {
    *process_id = 0;
    static const wchar_t* const active_database =
        ::makima::kernel::symbols::allocate_services_active_database_name(0x1414DA106ll);

    SC_HANDLE manager = ::OpenSCManagerW(
        nullptr,
        active_database,
        SC_MANAGER_CONNECT);
    if (manager == nullptr) return false;

    SC_HANDLE service = ::OpenServiceW(manager, service_name, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        (void)::CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD required = 0;
    const bool queried = ::QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status),
        sizeof(status),
        &required) != FALSE;
    if (queried) *process_id = status.dwProcessId;

    (void)::CloseServiceHandle(service);
    (void)::CloseServiceHandle(manager);
    return queried;
}

}
