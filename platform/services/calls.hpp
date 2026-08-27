#pragma once

#include <cstdint>

#include <windows.h>
#include <winsvc.h>

namespace makima::platform::services {

[[nodiscard]] bool call_query_service_status_ex(
    SC_HANDLE service,
    SERVICE_STATUS_PROCESS& status);


[[nodiscard]] bool query_service_process_id(
    const wchar_t* service_name,
    std::uint32_t* process_id) noexcept;

}
