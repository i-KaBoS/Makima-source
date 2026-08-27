#include "storage/services/services.hpp"

#include <windows.h>

#include <winsvc.h>

#include <cstddef>
#include <string>

namespace makima::storage::services {

char* allocate_lookup_privilege_value_w_import(
    const std::uint8_t* protected_source);
char* allocate_advapi32_dll(std::int64_t protected_source);
char* allocate_delete_service_import(
    const std::uint8_t* protected_source);
char* allocate_advapi32_for_delete_service(
    const std::uint8_t* protected_source);
char* allocate_adjust_token_privileges(std::int64_t protected_source);
char* allocate_advapi32_dll_for_adjust_token_privileges(
    const std::byte* protected_source);
char* allocate_open_scmanager_w(std::int64_t protected_source);
char* allocate_advapi32_dll_for_open_scmanager_w(
    std::int64_t protected_source);
char* allocate_open_service_w(const std::byte* protected_source);
char* allocate_advapi32_dll_for_open_service_w(
    std::int64_t protected_source);
char* allocate_control_service(std::int64_t protected_source);
char* allocate_advapi32_dll_for_control_service(
    std::int64_t protected_source);
char* allocate_close_service_handle(std::int64_t protected_source);
char* allocate_advapi32_dll_for_close_service_handle(
    std::int64_t protected_source);

namespace {

struct ServiceImportSlots final {
    FARPROC lookup_privilege_value{};
    FARPROC adjust_token_privileges{};
    FARPROC open_sc_manager{};
    FARPROC open_service{};
    FARPROC control_service{};
    FARPROC delete_service{};
    FARPROC close_service_handle{};
};

ServiceImportSlots service_imports{};

}


void resolve_lookup_privilege_value_import() noexcept {
    static const char* const api_name = allocate_lookup_privilege_value_w_import(
        reinterpret_cast<const std::uint8_t*>(0x1414D93C4ull));
    static const char* const module_name = allocate_advapi32_dll(
        0x1414D93DBll);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.lookup_privilege_value = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_adjust_token_privileges_import() noexcept {
    static const char* const api_name = allocate_adjust_token_privileges(
        0x1414D93E9ll);
    static const char* const module_name =
        allocate_advapi32_dll_for_adjust_token_privileges(
            reinterpret_cast<const std::byte*>(0x1414D9400ull));
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.adjust_token_privileges = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_open_sc_manager_import() noexcept {
    static const char* const api_name = allocate_open_scmanager_w(
        0x1414D940Ell);
    static const char* const module_name =
        allocate_advapi32_dll_for_open_scmanager_w(0x1414D941Ell);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.open_sc_manager = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_open_service_import() noexcept {
    static const char* const api_name = allocate_open_service_w(
        reinterpret_cast<const std::byte*>(0x1414D942Cull));
    static const char* const module_name =
        allocate_advapi32_dll_for_open_service_w(0x1414D943All);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.open_service = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_control_service_import() noexcept {
    static const char* const api_name = allocate_control_service(
        0x1414D9448ll);
    static const char* const module_name =
        allocate_advapi32_dll_for_control_service(0x1414D9458ll);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.control_service = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_delete_service_import() noexcept {
    static const char* const api_name = allocate_delete_service_import(
        reinterpret_cast<const std::uint8_t*>(0x1414D9466ull));
    static const char* const module_name = allocate_advapi32_for_delete_service(
        reinterpret_cast<const std::uint8_t*>(0x1414D9475ull));
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.delete_service = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}


void resolve_close_service_handle_import() noexcept {
    static const char* const api_name = allocate_close_service_handle(
        0x1414D9483ll);
    static const char* const module_name =
        allocate_advapi32_dll_for_close_service_handle(0x1414D9497ll);
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    service_imports.close_service_handle = module == nullptr
        ? nullptr : GetProcAddress(module, api_name);
}

bool stop_service(std::wstring_view name, unsigned long timeout_ms) noexcept {
    if (name.empty()) return false;
    const std::wstring owned_name{name};
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) return false;
    SC_HANDLE service = OpenServiceW(manager, owned_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS status{};
    bool stopped = ControlService(service, SERVICE_CONTROL_STOP, &status) != FALSE ||
        GetLastError() == ERROR_SERVICE_NOT_ACTIVE;
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    while (stopped && status.dwCurrentState != SERVICE_STOPPED && GetTickCount64() < deadline) {
        Sleep(50);
        stopped = QueryServiceStatus(service, &status) != FALSE;
    }
    stopped = stopped && status.dwCurrentState == SERVICE_STOPPED;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return stopped;
}

}
