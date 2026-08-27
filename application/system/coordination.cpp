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
#include "graphics/gdi/coordination.hpp"
#include "platform/windows/windows.hpp"
#include "security/identity/identity.hpp"
#include "telemetry/reporting/reporting.hpp"
#include "../../security/anti_analysis/anti_analysis.hpp"
#include "../../storage/registry/registry.hpp"
#include "security_startup.hpp"

namespace makima::application::shared {
bool initialize_async_security_capture() noexcept;
bool start_authenticated_request_worker() noexcept;
}

namespace makima::network::session {
bool write_current_user_sid_utf8(char* destination, int capacity) noexcept;
}

namespace makima::storage::registry {
wchar_t* allocate_makima_window_title(const std::uint16_t* protected_source);
wchar_t* allocate_close_any_debugging_or_analysis_tools_before_using_the_makima_loader(
    std::int64_t protected_source);
}

namespace makima::application::system {

std::uint32_t initialize_ole_registry_discovery_and_gdi(
    void* request_context,
    std::uint32_t fallback_object) noexcept {
    if (::makima::storage::registry::current_process_has_no_debug_port() == 0) return 0;
    if (::makima::security::anti_analysis::analysis_process_blacklist_check() == 0) {


        static const wchar_t* const title =
            ::makima::storage::registry::allocate_makima_window_title(
                reinterpret_cast<const std::uint16_t*>(0x1414DAD62ull));
        static const wchar_t* const warning =
            ::makima::storage::registry::
                allocate_close_any_debugging_or_analysis_tools_before_using_the_makima_loader(
                    0x1414DAD72ll);
        (void)::MessageBoxW(nullptr, warning, title, 0x30U);
        return 0;
    }
    if (!::makima::platform::windows::initialize_platform_api_bindings()) return 0;
    ::makima::telemetry::reporting::install_unhandled_exception_reporting();
    const HRESULT initialized = OleInitialize(nullptr);
    if (FAILED(initialized)) return false;
    struct OleScope final {
        ~OleScope() { OleUninitialize(); }
    } ole_scope;

    if (!::makima::graphics::gdi::initialize_edge_update_splash(request_context)) return 0;
    if (!::makima::application::shared::initialize_async_security_capture()) return 0;
    if (!::makima::application::shared::start_authenticated_request_worker()) return 0;
    HWND startup_window = nullptr;
    const bool has_startup_window =
        ::makima::security::identity::enumerate_windows_for_security_context(
            GetCurrentProcessId(), &startup_window);
    if (has_startup_window) RevertToSelf();
    std::array<char, 128> current_sid{};
    if (!::makima::network::session::write_current_user_sid_utf8(
            current_sid.data(), static_cast<int>(current_sid.size()))) {
        return 0;
    }
    const std::wstring module_path =
        ::makima::platform::windows::get_wide_module_file_path_for_update_event();
    if (module_path.empty()) return 0;
    HANDLE startup_semaphore = nullptr;
    if (::makima::platform::windows::acquire_named_process_mutex(
            "security-platform", &startup_semaphore) != ERROR_SUCCESS) {
        return 0;
    }
    const auto close_startup_semaphore =
        std::unique_ptr<void, decltype(&CloseHandle)>(startup_semaphore, CloseHandle);
    ::makima::platform::windows::WaitForSecurityEventRequest startup_wait{
        startup_semaphore, 0U, false, WAIT_FAILED};
    if (::makima::platform::windows::call_wait_for_single_object_ex(&startup_wait) == 0) {
        return 0;
    }
    LONG previous_count = 0;
    if (!::makima::platform::windows::call_release_semaphore(
            startup_semaphore, 1, &previous_count)) {
        return 0;
    }
    ::makima::graphics::gdi::SplashWindowState splash{};
    if (::makima::graphics::gdi::create_dpi_aware_splash_window(
            &splash,
            reinterpret_cast<HINSTANCE>(static_cast<std::uintptr_t>(fallback_object))) == 0) {
        return 0;
    }
    char* integrity_capture = ::makima::storage::registry::integrity_capture_buffer();
    if (!::makima::telemetry::reporting::schedule_integrity_capture_async(integrity_capture)) {
        return 0;
    }
    return 1;
}

}
