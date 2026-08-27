#pragma once

#include "platform/windows/windows.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <windows.h>

namespace makima::process::launch {

using NativeJobInformationRequest =
    ::makima::platform::windows::NativeJobInformationRequest;

struct ChildLaunchState final {
    HANDLE process{};
    std::uintptr_t image_base{};
    NativeJobInformationRequest* job_request{};
    HANDLE primary_thread{};
    HANDLE job{};
    std::uint32_t mapping_state{};
    std::array<std::byte, 0x1040 - 0x2c> state_storage{};
    std::uint32_t error_stage{};
    std::array<std::byte, 0x1098 - 0x1044> launch_storage{};
    NativeJobInformationRequest* owned_job_request{};
    std::uint64_t reserved{};
    std::uint32_t stage_complete{};
};

static_assert(offsetof(ChildLaunchState, error_stage) == 0x1040);
static_assert(offsetof(ChildLaunchState, owned_job_request) == 0x1098);
static_assert(offsetof(ChildLaunchState, stage_complete) == 0x10a8);

[[nodiscard]] std::uint64_t terminate_child_job_and_restore_impersonation(
    ChildLaunchState* state,
    std::uint32_t stage) noexcept;

}
