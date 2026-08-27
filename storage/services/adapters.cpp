#include "storage/services/services.hpp"
#include "process/pe_mapping/memory.hpp"

#include <windows.h>

#include <winsvc.h>

#include <cstring>
#include <new>
#include <string>
#include <string_view>
#include <vector>

namespace makima::storage::services {

GetCurrentProcessFunction resolved_get_current_process{};

namespace {

char* allocate_service_import_token(std::string_view token) {
    auto* output = static_cast<char*>(::operator new(token.size() + 1U));
    std::memcpy(output, token.data(), token.size());
    output[token.size()] = '\0';
    return output;
}

SC_HANDLE open_manager(DWORD access) noexcept {
    return OpenSCManagerW(nullptr, nullptr, access);
}

}





void initialize_get_current_process_import() noexcept {
    HMODULE const kernel32 = LoadLibraryA("kernel32.dll");
    if (kernel32 != nullptr) {
        resolved_get_current_process =
            reinterpret_cast<GetCurrentProcessFunction>(
                GetProcAddress(kernel32, "GetCurrentProcess"));
    }
}

namespace {



[[maybe_unused]] const bool current_process_import_initialized = []() noexcept {
    initialize_get_current_process_import();
    return true;
}();

}



char* allocate_lookup_privilege_value_w_import(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_service_import_token("LookupPrivilegeValueW");
}


char* allocate_delete_service_import(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_service_import_token("DeleteService");
}


char* allocate_advapi32_for_delete_service(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_service_import_token("advapi32.dll");
}



const char* local_allocation_failure_message() {
    static const char* message = allocate_local_alloc_failed(0x1414D952Bll);
    return message;
}


const char* remote_write_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_remote_write_failed_message(0x1414D953Fll);
    return value;
}


const char* thread_context_read_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_get_thread_context_failed_message(0x1414D9554ll);
    return value;
}


const char* stub_allocation_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_stub_alloc_failed_message(0x1414D956Dll);
    return value;
}


const char* thread_context_write_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_set_thread_context_failed_message(0x1414D9580ll);
    return value;
}


const char* remote_thread_creation_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_nt_create_thread_ex_failed_message(0x1414D9599ll);
    return value;
}


const char* resumed_process_exit_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_process_exited_after_resume_message(0x1414D95B2ll);
    return value;
}


const char* stub_buffer_allocation_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_alloc_failed_for_stub_message(0x1414D9746ll);
    return value;
}


const char* secondary_remote_thread_creation_failure_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_secondary_nt_create_thread_ex_failed_message(
                0x1414D975Dll);
    return value;
}


const char* injection_timeout_message() noexcept {
    static const char* value =
        ::makima::process::pe_mapping::literals::
            allocate_injection_timed_out_15s_message(0x1414D9776ll);
    return value;
}

ServiceSnapshot query_service(std::wstring_view name) noexcept {
    ServiceSnapshot snapshot{std::wstring{name}};
    if (name.empty()) return snapshot;
    SC_HANDLE manager = open_manager(SC_MANAGER_CONNECT);
    if (manager == nullptr) return snapshot;
    SC_HANDLE service = OpenServiceW(
        manager,
        snapshot.name.c_str(),
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        CloseServiceHandle(manager);
        return snapshot;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD needed = 0;
    if (QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<BYTE*>(&status),
            sizeof(status),
            &needed)) {
        snapshot.state = status.dwCurrentState;
    }
    QueryServiceConfigW(service, nullptr, 0, &needed);
    if (needed != 0) {
        std::vector<std::byte> buffer(needed);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
        if (QueryServiceConfigW(service, config, needed, &needed)) {
            snapshot.start_type = config->dwStartType;
        }
    }
    snapshot.present = true;
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return snapshot;
}

bool configure_service_start(std::wstring_view name, unsigned long start_type) noexcept {
    if (name.empty()) return false;
    const std::wstring owned_name{name};
    SC_HANDLE manager = open_manager(SC_MANAGER_CONNECT);
    if (manager == nullptr) return false;
    SC_HANDLE service = OpenServiceW(manager, owned_name.c_str(), SERVICE_CHANGE_CONFIG);
    const bool changed = service != nullptr && ChangeServiceConfigW(
        service,
        SERVICE_NO_CHANGE,
        start_type,
        SERVICE_NO_CHANGE,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr);
    if (service != nullptr) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return changed;
}

}
