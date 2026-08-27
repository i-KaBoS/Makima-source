#include "process/launch/coordination.hpp"

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

namespace makima::process::launch {

extern "C" NTSTATUS NTAPI NtTerminateJobObject(HANDLE job, NTSTATUS status);
extern "C" NTSTATUS NTAPI NtTerminateProcess(HANDLE process, NTSTATUS status);
extern "C" NTSTATUS NTAPI NtWaitForSingleObject(HANDLE object, BOOLEAN alertable, LARGE_INTEGER* timeout);

std::uint64_t terminate_child_job_and_restore_impersonation(
    ChildLaunchState* state,
    std::uint32_t stage) noexcept {
    if (state == nullptr) return 0;

    if (state->owned_job_request == nullptr) {
        state->owned_job_request = new (std::nothrow) NativeJobInformationRequest{};
        if (state->owned_job_request == nullptr) {
            state->error_stage = 9;
            state->stage_complete = 0;
            return 0;
        }
    }

    if (!::makima::platform::windows::call_nt_set_information_job_object(state->owned_job_request)) {
        state->error_stage = 9;
        state->stage_complete = 0;
        RevertToSelf();
        if (state->owned_job_request->job != nullptr) {
            NtTerminateJobObject(state->owned_job_request->job, 0);
        }
        delete std::exchange(state->owned_job_request, nullptr);
        return 0;
    }

    state->stage_complete = 1;
    if (stage < 2) return 1;
    if (state->process == nullptr) {
        state->error_stage = 11;
        return 0;
    }
    if (stage >= 4 && state->primary_thread != nullptr) {
        const NTSTATUS wait_status = NtWaitForSingleObject(state->primary_thread, FALSE, nullptr);
        if (wait_status < 0) {
            state->error_stage = 13;
            NtTerminateProcess(state->process, wait_status);
            return 0;
        }
    }
    if (stage >= 8 && RevertToSelf() == FALSE) {
        state->error_stage = 13;
        return 0;
    }
    std::fflush(nullptr);
    return 1;
}

}
