#include "kernel/silo/silo.hpp"

#include <windows.h>
#include <winternl.h>

#include <array>
#include <cwchar>

extern "C" {
NTSYSAPI NTSTATUS NTAPI NtOpenDirectoryObject(
    PHANDLE directory_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes);
NTSYSAPI NTSTATUS NTAPI NtCreateDirectoryObjectEx(
    PHANDLE directory_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    HANDLE shadow_directory_handle,
    ULONG flags);
NTSYSAPI NTSTATUS NTAPI NtClose(HANDLE handle);
}

namespace makima::kernel::silo {
namespace {

void close_handle(NativeApi& api, NativeHandle handle) noexcept {
    if (handle != 0 && api.close) {
        try {
            api.close(handle);
        } catch (...) {
        }
    }
}

}


NativeHandle create_process_in_silo(
    SiloContext& context,
    NativeApi& api) {
    if (!api.create_process_in_job) {
        throw_native_api_unavailable();
    }
    const auto created_process = api.create_process_in_job(context.job);
    if (created_process == 0) {
        return 0;
    }
    if (context.job != 0) {
        if (!api.assign_process_to_job ||
            !api.assign_process_to_job(context.job, created_process).success()) {
            close_handle(api, created_process);
            return 0;
        }
    }
    if (context.process != 0 && context.process != created_process) {
        close_handle(api, context.process);
    }
    context.process = created_process;
    return created_process;
}


bool create_and_assign_silo_job(SiloContext& context, NativeApi& api) {
    if (context.job != 0) {
        return context.process == 0 ||
               (api.assign_process_to_job &&
                api.assign_process_to_job(context.job, context.process).success());
    }
    if (!api.create_job || !api.configure_silo_job) {
        throw_native_api_unavailable();
    }

    const auto created_job = api.create_job();
    if (created_job == 0) {
        return false;
    }
    if (!api.configure_silo_job(created_job).success()) {
        close_handle(api, created_job);
        return false;
    }
    if (context.process != 0 &&
        (!api.assign_process_to_job ||
         !api.assign_process_to_job(created_job, context.process).success())) {
        close_handle(api, created_job);
        return false;
    }
    context.job = created_job;
    return true;
}



bool create_device_directory_child(
    const void* reserved_context,
    const wchar_t* directory_prefix) noexcept {
    (void)reserved_context;
    if (directory_prefix == nullptr) {
        return false;
    }

    std::array<wchar_t, 0x104> child_name_text{};
    if (swprintf_s(
            child_name_text.data(),
            child_name_text.size(),
            L"%ws\\Device",
            directory_prefix) < 0) {
        return false;
    }

    wchar_t root_name_text[] = L"\\Device";
    UNICODE_STRING root_name{
        static_cast<USHORT>((std::size(root_name_text) - 1) * sizeof(wchar_t)),
        static_cast<USHORT>(std::size(root_name_text) * sizeof(wchar_t)),
        root_name_text,
    };
    OBJECT_ATTRIBUTES root_attributes{};
    InitializeObjectAttributes(
        &root_attributes,
        &root_name,
        OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    HANDLE root_directory = nullptr;
    const auto open_status = NtOpenDirectoryObject(
        &root_directory,
        MAXIMUM_ALLOWED,
        &root_attributes);
    if (open_status < 0) {
        return false;
    }

    UNICODE_STRING child_name{
        static_cast<USHORT>(std::wcslen(child_name_text.data()) * sizeof(wchar_t)),
        static_cast<USHORT>((std::wcslen(child_name_text.data()) + 1) * sizeof(wchar_t)),
        child_name_text.data(),
    };
    OBJECT_ATTRIBUTES child_attributes{};
    InitializeObjectAttributes(
        &child_attributes,
        &child_name,
        OBJ_OPENIF | OBJ_PERMANENT | OBJ_CASE_INSENSITIVE,
        nullptr,
        nullptr);

    HANDLE child_directory = nullptr;
    const auto create_status = NtCreateDirectoryObjectEx(
        &child_directory,
        MAXIMUM_ALLOWED,
        &child_attributes,
        root_directory,
        0);
    if (child_directory != nullptr) {
        NtClose(child_directory);
    }
    NtClose(root_directory);
    return create_status >= 0;
}

}
