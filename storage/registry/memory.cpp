#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <intrin.h>

#include "storage/registry/registry.hpp"
#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"
#include "application/shared/pipelines.hpp"
#include "ui/webview2_runtime.hpp"

#include <windows.h>
#include <WebView2.h>
#include <WebView2EnvironmentOptions.h>
#include <wrl.h>

#include <string>

namespace makima::runtime::payload_state {




makima::payload::crypto::EcdhSession* active_ecdh_session{};
std::array<std::byte, 0x40> ecdh_cleanup_state{};
std::array<std::byte, 0x2db8> payload_scratch{};

}

namespace makima::storage::registry {



ProcessStorageReference* process_storage_release_dependency{};



GuardShutdownCallback guard_shutdown_callback{};






void release_process_storage_reference(
    ProcessStorageReference* reference) noexcept {
    auto* const count = reinterpret_cast<volatile long*>(
        &reference->reference_count);
    long observed = *count;
    long replacement{};

    if (observed == (std::numeric_limits<std::int32_t>::max)()) {
        replacement = observed - 1;
    } else {
        for (;;) {
            replacement = observed - 1;
            const long prior =
                _InterlockedCompareExchange(count, replacement, observed);
            if (prior == observed) {
                break;
            }
            observed = prior;
        }
    }

    if (replacement != 0) {
        return;
    }

    reference->vtable->destroy_reference(reference, 1);

    ProcessStorageReference* const dependency =
        process_storage_release_dependency;
    if (dependency != nullptr) {
        dependency->vtable->release_dependency(dependency);
    }
}




void release_active_ecdh_runtime_state() noexcept {
    using runtime::payload_state::active_ecdh_session;

    if (active_ecdh_session != nullptr) {
        payload::crypto::destroy_ecdh_session(*active_ecdh_session);

        payload::crypto::EcdhSession* const allocation =
            active_ecdh_session;
        if (allocation != nullptr) {
            application::shared::cleanup_ecdh_session_import_bindings(
                *allocation);
            ::operator delete(allocation, sizeof(*allocation));
        }
        active_ecdh_session = nullptr;
    }

    runtime::payload_state::ecdh_cleanup_state.fill(std::byte{});
}



void release_owned_process_storage() noexcept {
    release_active_ecdh_runtime_state();
    runtime::payload_state::payload_scratch.fill(std::byte{});
}




void release_guard_backed_process_storage(char* storage) noexcept {
    if (guard_shutdown_callback != nullptr) {
        guard_shutdown_callback();
    }
    storage[0] = '\0';
}

bool read_protocol_command(std::wstring_view scheme, std::wstring& command) noexcept {
    command.clear();
    if (scheme.empty()) return false;
    const std::wstring path =
        L"Software\\Classes\\" + std::wstring{scheme} + L"\\shell\\open\\command";
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, KEY_QUERY_VALUE, &key) !=
        ERROR_SUCCESS) {
        return false;
    }

    DWORD type = 0;
    DWORD bytes = 0;
    LSTATUS status = RegQueryValueExW(key, nullptr, nullptr, &type, nullptr, &bytes);
    if (status != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) ||
        bytes < sizeof(wchar_t)) {
        RegCloseKey(key);
        return false;
    }

    command.resize(bytes / sizeof(wchar_t));
    status = RegQueryValueExW(
        key,
        nullptr,
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(command.data()),
        &bytes);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS) {
        command.clear();
        return false;
    }
    while (!command.empty() && command.back() == L'\0') command.pop_back();
    return true;
}



std::string* write_primary_guard_success_response(std::string* output) {


    makima::payload::crypto::detail::release_active_ecdh_runtime_state();
    static const char* const response =
        allocate_ok_true_json_response(0x1414DE9E6ll);
    *output = response;
    return output;
}



std::string* write_secondary_guard_success_response(std::string* output) {
    static const char* const response =
        allocate_secondary_ok_true_json_response(
            reinterpret_cast<const std::byte*>(0x1414DEAB8ull));
    *output = response;
    return output;
}










std::uint64_t create_edge_update_webview_environment(
    std::int64_t webview_owner) noexcept {
    std::array<wchar_t, 0x104> cache_path{};
    static const wchar_t* const local_app_data_name =
        allocate_localappdata_for_edge_update_cache_path(
            reinterpret_cast<const std::uint16_t*>(0x1414DF0F6ull));
    const DWORD length = GetEnvironmentVariableW(
        local_app_data_name, cache_path.data(),
        static_cast<DWORD>(cache_path.size()));
    if (length == 0 || length >= cache_path.size()) return 0;
    static const wchar_t* const cache_suffix =
        allocate_microsoft_edge_update_cache(0x1414DF112ll);
    (void)wcscat_s(
        cache_path.data(), cache_path.size(), cache_suffix);
    CreateDirectoryW(cache_path.data(), nullptr);

    auto options = Microsoft::WRL::Make<CoreWebView2EnvironmentOptions>();
    static const wchar_t* const browser_arguments =
        allocate_enable_features_mswebview2enabledraggableregions_disable(
            0x1414DF14Cll);
    (void)options->put_AdditionalBrowserArguments(browser_arguments);

    auto* const completion =
        ui::create_edge_update_environment_completion_handler(
            reinterpret_cast<void*>(webview_owner));
    const HRESULT result = CreateCoreWebView2EnvironmentWithOptions(
        nullptr,
        cache_path.data(),
        options.Get(),
        completion);
    completion->Release();
    if (FAILED(result)) {
        makima::application::shared::report_webview_environment_creation_failure(
            result);
    }
    const std::uint32_t preserved_caller_bits =
        static_cast<std::uint32_t>(webview_owner) & 0xffffff00U;
    return preserved_caller_bits | (SUCCEEDED(result) ? 1U : 0U);
}


wchar_t* allocate_quoted_executable_and_url_argument_template(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"\"%s\" \"%%1\"";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_loader_protocol_registry_path(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Software\\Classes\\makima-loader";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_loader_protocol_display_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"URL:Application Protocol";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_url_protocol_registry_value_name(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"URL Protocol";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_default_icon_registry_key_name(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr wchar_t decoded_value[] = L"DefaultIcon";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_quoted_executable_icon_index_zero_template(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"\"%s\",0";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_shell_registry_key_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"shell";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_open_registry_key_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"open";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_command_registry_key_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"command";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_local_edge_update_service_lock(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Local\\EdgeUpdate.ServiceLock";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_makima_window_title(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Makima";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_close_any_debugging_or_analysis_tools_before_using_the_makima_loader(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Close any debugging or analysis tools before using the Makima loader.";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_chrome_131_windows_user_agent(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


char* allocate_check_manual_map_of_guard_dll_returned_invalid_mapping(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "{\"check\":\"manualMap of guard DLL returned invalid mapping\"}";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_guard_init(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "GuardInit";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_guard_verify_integrity(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "GuardVerifyIntegrity";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_check_guard_init_export_not_found_in_mapped_guard_dll(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "{\"check\":\"GuardInit export not found in mapped guard DLL\"}";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_code_encrypt_guard_init_missing(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "code_encrypt.guard_init_missing";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_code_encrypt_guard_init_exception(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "code_encrypt.guard_init_exception";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


wchar_t* allocate_shcore_dll(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"shcore.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_shcore_dll_for_dpi_window(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"shcore.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_localappdata(const std::int16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"LOCALAPPDATA";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_microsoft_edge_update_splash(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"\\Microsoft\\EdgeUpdate\\Splash";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


char* allocate_ok_true_json_response(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "{\"ok\":true}";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_secondary_ok_true_json_response(
    const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "{\"ok\":true}";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


wchar_t* allocate_localappdata_for_edge_update_cache_path(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"LOCALAPPDATA";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_microsoft_edge_update_cache(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"\\Microsoft\\EdgeUpdate\\Cache";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}





wchar_t* allocate_enable_features_mswebview2enabledraggableregions_disable(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"--enable-features=msWebView2EnableDraggableRegions --disable-features=msSmartScreenProtection,Translate --autoplay-policy=no-user-gesture-required";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}

}
