#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
#include <process.h>
#include "pipelines.hpp"

namespace makima::application::shared {

unsigned __stdcall run_environment_probe_thread(void* owned_start_token) noexcept {
    coordinate_dwm_timing_path_and_authenticated_request();
    std::free(owned_start_token);
    return 0;
}

bool start_authenticated_request_worker() noexcept {
    void* start_token = std::malloc(1);
    if (start_token == nullptr) return false;

    unsigned thread_id = 0;
    const uintptr_t thread = _beginthreadex(
        nullptr, 0, run_environment_probe_thread, start_token, 0, &thread_id);
    if (thread == 0 || thread_id == 0) {
        std::free(start_token);
        return false;
    }
    CloseHandle(reinterpret_cast<HANDLE>(thread));
    return true;
}




wchar_t* allocate_update_progress_document_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] =
        L"{\"event\":\"update_progress\",\"data\":{\"status\":\"%hs\",\"percent\":%d}}";
    static_assert(sizeof(value) == 130U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

}
