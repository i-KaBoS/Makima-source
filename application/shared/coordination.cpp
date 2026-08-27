#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
#include <intrin.h>
#include <winhttp.h>
#include <shellapi.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include "../../payload/crypto/crypto_internal.hpp"
#include "../../platform/include/makima/platform/security_monitor.hpp"
#include "telemetry/reporting/reporting.hpp"
#include "pipelines.hpp"

namespace makima::network::session {
bool write_current_user_sid_utf8(char* destination, int capacity) noexcept;
bool send_authenticated_request(const std::byte* data, std::size_t size) noexcept;





}

namespace makima::application::shared {

namespace {




std::byte application_shared_runtime_context_storage{};
decltype(&WinHttpConnect) winhttp_connect_import{};
decltype(&WinHttpReceiveResponse) winhttp_receive_response_import{};
decltype(&WinHttpQueryDataAvailable) winhttp_query_data_available_import{};
decltype(&GetFileAttributesW) get_file_attributes_w_import{};
decltype(&WinHttpOpenRequest) winhttp_open_request_import{};
decltype(&WinHttpSendRequest) winhttp_send_request_import{};
decltype(&WinHttpReadData) winhttp_read_data_import{};
decltype(&WinHttpCloseHandle) winhttp_close_handle_import{};
decltype(&BCryptDestroyKey) bcrypt_destroy_key_import{};
decltype(&BCryptCloseAlgorithmProvider) bcrypt_close_algorithm_provider_import{};

template <class Procedure>
[[nodiscard]] Procedure resolve_dynamic_procedure_fallback(
    const char* module_name,
    const char* procedure_name) noexcept {
    if (module_name == nullptr || procedure_name == nullptr) return nullptr;
    HMODULE module = GetModuleHandleA(module_name);
    if (module == nullptr) module = LoadLibraryA(module_name);
    const FARPROC address = module == nullptr
        ? nullptr : GetProcAddress(module, procedure_name);
    Procedure procedure{};
    static_assert(sizeof(procedure) == sizeof(address));
    std::memcpy(&procedure, &address, sizeof(procedure));
    return procedure;
}

}





void* get_application_shared_runtime_context() noexcept {
    return &application_shared_runtime_context_storage;
}



void bind_winhttp_connect() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_winhttp_connect_api_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8CB9ull));
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_winhttp_module_for_connect(
            reinterpret_cast<const std::uint8_t*>(0x1414D8CC9ull));
    winhttp_connect_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_connect_import)>(
        module_name, procedure_name);
}



decltype(&GetFileAttributesW) bind_get_file_attributes_w() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_file_attributes_api_name(
            0x1414D8C97ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_file_attributes_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8CABull));
    get_file_attributes_w_import =
        resolve_dynamic_procedure_fallback<decltype(get_file_attributes_w_import)>(
            module_name, procedure_name);
    return get_file_attributes_w_import;
}


decltype(&WinHttpOpenRequest) bind_winhttp_open_request() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_http_open_request_api_name(
            0x1414D8CD6ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_open_request_module_name(
            0x1414D8CEAll, __readgsqword(0x58));
    winhttp_open_request_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_open_request_import)>(
            module_name, procedure_name);
    return winhttp_open_request_import;
}


decltype(&WinHttpSendRequest) bind_winhttp_send_request() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_http_send_request_api_name(
            0x1414D8CF7ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_send_request_module_name(
            reinterpret_cast<const char*>(0x1414D8D0Bull));
    winhttp_send_request_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_send_request_import)>(
            module_name, procedure_name);
    return winhttp_send_request_import;
}


decltype(&WinHttpReadData) bind_winhttp_read_data() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_http_read_data_api_name(
            0x1414D8D65ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_read_data_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8D76ull));
    winhttp_read_data_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_read_data_import)>(
            module_name, procedure_name);
    return winhttp_read_data_import;
}


decltype(&WinHttpCloseHandle) bind_winhttp_close_handle() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_http_close_handle_api_name(
            0x1414D8D83ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_close_handle_module_name(
            0x1414D8D97ll);
    winhttp_close_handle_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_close_handle_import)>(
            module_name, procedure_name);
    return winhttp_close_handle_import;
}


void bind_winhttp_receive_response() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_winhttp_receive_response_api_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8D18ull));
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_receive_response_module_name(
            0x1414D8D30ll);
    winhttp_receive_response_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_receive_response_import)>(
            module_name, procedure_name);
}


void bind_winhttp_query_data_available() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_winhttp_query_available_api_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8D3Dull));
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_http_query_available_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8D58ull));
    winhttp_query_data_available_import =
        resolve_dynamic_procedure_fallback<decltype(winhttp_query_data_available_import)>(
            module_name, procedure_name);
}




decltype(&BCryptDestroyKey) resolve_bcrypt_destroy_key() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_bcrypt_destroy_key_api_name(
            0x1414D8E59ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_bcrypt_destroy_key_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8E6Bull));
    bcrypt_destroy_key_import =
        resolve_dynamic_procedure_fallback<decltype(bcrypt_destroy_key_import)>(
            module_name, procedure_name);
    return bcrypt_destroy_key_import;
}




decltype(&BCryptCloseAlgorithmProvider)
resolve_bcrypt_close_algorithm_provider() noexcept {
    static const char* const procedure_name =
        ::makima::payload::crypto::detail::allocate_bcrypt_close_provider_api_name(
            0x1414D8E14ll);
    static const char* const module_name =
        ::makima::payload::crypto::detail::allocate_bcrypt_close_provider_module_name(
            reinterpret_cast<const std::uint8_t*>(0x1414D8E32ull));
    bcrypt_close_algorithm_provider_import =
        resolve_dynamic_procedure_fallback<decltype(bcrypt_close_algorithm_provider_import)>(
            module_name, procedure_name);
    return bcrypt_close_algorithm_provider_import;
}

std::array<char, 128> current_user_sid_utf8{};

bool initialize_async_security_capture() noexcept {
    current_user_sid_utf8[0] = '\0';
    if (!::makima::telemetry::reporting::schedule_security_capture_async()) return false;
    return ::makima::network::session::write_current_user_sid_utf8(
        current_user_sid_utf8.data(), static_cast<int>(current_user_sid_utf8.size()));
}

bool coordinate_authenticated_request_and_derive_payload_keys(
    AuthenticatedRequestContext* context,
    const char* request) noexcept {
    if (context == nullptr || request == nullptr || *request == '\0') return false;
    const auto request_size = std::strlen(request);
    const auto* bytes = reinterpret_cast<const std::byte*>(request);
    if (::makima::payload::crypto::derive_payload_keys(
            context->key,
            bytes,
            request_size,
            reinterpret_cast<const std::byte*>(current_user_sid_utf8.data()),
            std::char_traits<char>::length(current_user_sid_utf8.data()),
            context->derived_key) == 0) {
        return false;
    }
    return ::makima::network::session::send_authenticated_request(
        context->derived_key.data(), context->derived_key.size());
}

bool coordinate_dwm_timing_path_and_authenticated_request() noexcept {
    const auto timing = ::makima::platform::query_desktop_timing();
    const std::string report =
        std::string{"{\"composition_enabled\":"} +
        (timing.composition_enabled ? "true" : "false") +
        ",\"refresh_counter\":" + std::to_string(timing.refresh_counter) +
        ",\"qpc_refresh_period\":" + std::to_string(timing.qpc_refresh_period) +
        ",\"qpc_vblank\":" + std::to_string(timing.qpc_vblank) + "}";
    return ::makima::network::session::send_authenticated_request(
        reinterpret_cast<const std::byte*>(report.data()), report.size());
}


void report_webview_environment_creation_failure(
    std::int32_t hresult) noexcept {
    constexpr wchar_t runtime_error[] =
        L"Makima Loader requires Microsoft Edge WebView2 Runtime, which is "
        L"missing or could not be loaded.\n\nClick OK to open the official ";
    (void)hresult;
    if (MessageBoxW(
            nullptr,
            runtime_error,
            L"Makima Loader",
            MB_OKCANCEL | MB_ICONERROR | MB_SETFOREGROUND | MB_TOPMOST) ==
        IDOK) {
        ShellExecuteW(
            nullptr,
            L"open",
            L"https://go.microsoft.com/fwlink/p/?LinkId=2124703",
            nullptr,
            nullptr,
            SW_SHOWNORMAL);
    }
}

}
