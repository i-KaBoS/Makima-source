#include "kernel/silo/server_silo_lifetime.hpp"

#include <cstdlib>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

extern "C" NTSTATUS NTAPI NtClose(HANDLE handle);
extern "C" NTSTATUS NTAPI NtTerminateJobObject(HANDLE job_handle, NTSTATUS exit_status);

namespace makima::kernel::silo {
namespace {

[[nodiscard]] HANDLE windows_handle(NativeHandle handle) noexcept {
    return reinterpret_cast<HANDLE>(handle);
}

}


ServerSiloLifetime::~ServerSiloLifetime() noexcept {
    if (job != 0) {
        static_cast<void>(NtTerminateJobObject(windows_handle(job), static_cast<NTSTATUS>(0)));
        static_cast<void>(NtClose(windows_handle(job)));
    }

    if (deletion_event != 0) {
        static_cast<void>(CloseHandle(windows_handle(deletion_event)));
    }

    std::free(root_path);
}

}
