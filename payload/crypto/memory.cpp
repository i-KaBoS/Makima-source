#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"
#include "process/pe_mapping/pe_mapping.hpp"
#include "application/shared/pipelines.hpp"
#include "storage/registry/registry.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <ranges>
#include <string_view>
#include <utility>

extern "C" void __cdecl _Cnd_do_broadcast_at_thread_exit();

namespace makima::payload::crypto {

namespace detail {

namespace {

char* allocate_persistent_ansi(std::string_view value) {
    auto* storage = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(storage, value.data(), value.size());
    storage[value.size()] = '\0';
    return storage;
}

wchar_t* allocate_persistent_utf16(std::wstring_view value) {
    auto* storage = static_cast<wchar_t*>(
        ::operator new((value.size() + 1U) * sizeof(wchar_t)));
    std::memcpy(storage, value.data(), value.size() * sizeof(wchar_t));
    storage[value.size()] = L'\0';
    return storage;
}

void copy_mapping_error(char* destination, const char* message) noexcept {
    if (destination != nullptr) {
        strncpy_s(destination, 0x100, message, _TRUNCATE);
    }
}

}





void release_active_ecdh_runtime_state() noexcept {
    ::makima::storage::registry::release_active_ecdh_runtime_state();
}



[[nodiscard]] std::uint64_t map_payload_into_suspended_host(
    char* error_buffer,
    const void* payload,
    std::size_t payload_size,
    const char* relative_host_image) noexcept {
    if (error_buffer != nullptr) *error_buffer = '\0';
    if (error_buffer == nullptr || payload == nullptr || payload_size == 0 ||
        relative_host_image == nullptr || *relative_host_image == '\0') {
        static const char* const message =
            allocate_suspended_host_invalid_arguments_error(0x1414D94C0ll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }

    const PeImageView image = inspect_pe_image(payload, payload_size);
    if (!image.valid || pe_virtual_image_size(image) == 0U ||
        pe_header_copy_size(image) == 0U) {
        static const char* const message =
            allocate_suspended_host_invalid_image_error(0x1414D94D3ll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }
    (void)pe_preferred_image_base(image);
    (void)pe_entry_point_rva(image);
    (void)pe_stack_reserve_size(image);
    (void)pe_stack_commit_size(image);
    for (std::uint16_t index = 0; index < pe_section_count(image); ++index) {
        MappedPeSection section{};
        read_pe_section(image, section, static_cast<int>(index));
    }

    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto create_process = kernel32 == nullptr ? nullptr :
        reinterpret_cast<decltype(&::CreateProcessW)>(
            GetProcAddress(kernel32, "CreateProcessW"));
    const auto resume_thread = kernel32 == nullptr ? nullptr :
        reinterpret_cast<decltype(&::ResumeThread)>(
            GetProcAddress(kernel32, "ResumeThread"));
    if (create_process == nullptr || resume_thread == nullptr) {
        static const char* const message =
            allocate_suspended_host_api_resolution_error(0x1414D94E7ll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }

    std::array<wchar_t, 0x104> current_directory{};
    if (GetCurrentDirectoryW(
            static_cast<DWORD>(current_directory.size()),
            current_directory.data()) == 0) {
        static const char* const message =
            allocate_suspended_host_api_resolution_error(0x1414D94E7ll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }
    std::wstring host_path{current_directory.data()};
    host_path.push_back(L'\\');
    while (*relative_host_image != '\0') {
        host_path.push_back(static_cast<unsigned char>(*relative_host_image++));
    }

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    if (!create_process(
            host_path.c_str(), nullptr, nullptr, nullptr, FALSE,
            CREATE_SUSPENDED, nullptr, nullptr, &startup, &process)) {
        static const char* const message =
            allocate_suspended_host_creation_error(0x1414D94FFll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }

    std::uint64_t mapped = 0;
    try {
        const auto* bytes = static_cast<const std::uint8_t*>(payload);
        const auto result = ::makima::process::pe_mapping::manual_map_pe_dll(
            process.dwProcessId,
            std::span<const std::uint8_t>{bytes, payload_size});
        mapped = result.image_base != 0U ? 1U : 0U;
    } catch (...) {
        mapped = 0;
    }
    if (mapped == 0) {
        static const char* const message =
            allocate_suspended_host_remote_allocation_error(0x1414D9516ll);
        copy_mapping_error(error_buffer, message);
    } else if (resume_thread(process.hThread) == static_cast<DWORD>(-1)) {
        mapped = 0;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return mapped;
}



[[nodiscard]] std::uint64_t map_payload_with_remote_loader(
    char* error_buffer,
    HANDLE process,
    const void* payload,
    std::size_t payload_size) noexcept {
    if (error_buffer != nullptr) *error_buffer = '\0';

    const PeImageView image = inspect_pe_image(payload, payload_size);
    if (error_buffer == nullptr || process == nullptr || !image.valid) {
        static const char* const message =
            allocate_remote_loader_local_api_resolution_error(0x1414D967Fll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }
    (void)pe_virtual_image_size(image);
    (void)pe_preferred_image_base(image);
    (void)pe_entry_point_rva(image);
    (void)pe_header_copy_size(image);
    for (std::uint16_t index = 0; index < pe_section_count(image); ++index) {
        MappedPeSection section{};
        read_pe_section(image, section, static_cast<int>(index));
    }

    static const wchar_t* const kernel_module =
        allocate_remote_loader_kernel_module_name(0x1414D96D2ll);
    static const wchar_t* const native_module =
        allocate_remote_loader_native_module_name(
            reinterpret_cast<const std::uint16_t*>(0x1414D96EEull));
    static const char* const local_api =
        allocate_runtime_function_table_api_name(0x1414D9704ll);
    static const char* const remote_api =
        allocate_remote_runtime_function_table_api_name(0x1414D9719ll);
    const HMODULE kernel32 = GetModuleHandleW(kernel_module);
    const HMODULE ntdll = GetModuleHandleW(native_module);
    if (kernel32 == nullptr || ntdll == nullptr ||
        GetProcAddress(kernel32, local_api) == nullptr ||
        GetProcAddress(ntdll, remote_api) == nullptr) {
        static const char* const message =
            allocate_remote_loader_local_api_resolution_error(0x1414D967Fll);
        copy_mapping_error(error_buffer, message);
        return 0;
    }

    try {
        const DWORD process_id = GetProcessId(process);
        const auto* bytes = static_cast<const std::uint8_t*>(payload);
        const auto result = ::makima::process::pe_mapping::manual_map_pe_dll(
            process_id,
            std::span<const std::uint8_t>{bytes, payload_size});
        if (result.image_base == 0U) {
            static const char* const message =
                allocate_remote_virtual_memory_allocation_error(0x1414D969Dll);
            copy_mapping_error(error_buffer, message);
            return 0;
        }
        return 1;
    } catch (const std::bad_alloc&) {
        static const char* const message =
            allocate_remote_loader_local_allocation_error(0x1414D96BDll);
        copy_mapping_error(error_buffer, message);
        return 0;
    } catch (const ::makima::process::pe_mapping::MappingError&) {
        static const char* const message =
            allocate_remote_loader_parameter_allocation_error(0x1414D972Ell);
        copy_mapping_error(error_buffer, message);
        return 0;
    } catch (...) {
        static const char* const message =
            allocate_remote_loader_parameter_allocation_error(0x1414D972Ell);
        copy_mapping_error(error_buffer, message);
        return 0;
    }
}

struct BootstrapStatusWorkItem final {
    ::makima::application::shared::BootstrapStatusPayload* destination{};
    const std::string* message{};
    const std::string* channel{};
    std::byte* published{};
};

static_assert(sizeof(BootstrapStatusWorkItem) == 0x20);

char* allocate_bootstrap_stable_release_channel(
    const std::uint8_t* protected_source);





std::uint64_t complete_bootstrap_status_work_item(
    BootstrapStatusWorkItem* work_item) {
    auto* runtime_context =
        ::makima::application::shared::get_application_shared_runtime_context();
    const char* channel = work_item->channel->c_str();
    if (work_item->channel->empty()) {
        static const char* const stable_channel =
            allocate_bootstrap_stable_release_channel(
                reinterpret_cast<const std::uint8_t*>(0x1414DEB02ull));
        channel = stable_channel;
    }

    ::makima::application::shared::BootstrapStatusPayload result;
    (void)::makima::application::shared::construct_bootstrap_status_payload(
        runtime_context,
        &result,
        work_item->message->c_str(),
        channel);

    auto* const destination = work_item->destination->bytes.data();
    const auto* const source = result.bytes.data();
    destination[0x80] = source[0x80];
    std::memcpy(destination + 0x60, source + 0x60, 0x20);
    std::memcpy(destination + 0x40, source + 0x40, 0x20);
    std::memcpy(destination + 0x20, source + 0x20, 0x20);
    std::memcpy(destination, source, 0x20);
    *work_item->published = std::byte{1};
    _Cnd_do_broadcast_at_thread_exit();
    ::operator delete(work_item, sizeof(*work_item));
    return 0;
}



void resize_owned_storage(
    std::vector<std::byte>& storage,
    std::size_t size,
    const std::byte& fill) {
    storage.resize(size, fill);
}








char* allocate_discord_login_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Discord login failed.");
}


char* allocate_login_invalid_server_response(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid server response.");
}


char* allocate_sync_invalid_server_response(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid server response.");
}


char* allocate_clock_skew_guidance(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "Your Windows clock is %lld seconds out of sync with our servers. "
        "Right-click the taskbar clock → Adjust date/time → Sync now.");
}


char* allocate_clock_skew_code(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("clock_skew");
}


char* allocate_websocket_protocol_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("makima-ws-v1");
}


char* allocate_websocket_transport_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("websocket");
}


char* allocate_detection_state_token(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("detected");
}


char* allocate_subscription_required_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("No active subscription for this product.");
}


char* allocate_no_payload_code(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("no payload");
}


char* allocate_branch_has_no_payload_message(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("No payload available for this branch.");
}


char* allocate_session_creation_failed_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to create session.");
}


char* allocate_invalid_session_response_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid session response.");
}


char* allocate_secure_session_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Creating secure session");
}


char* allocate_dma_dependency_download_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to download DMA dependencies.");
}


char* allocate_payload_product_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("destiny2");
}


char* allocate_resource_fetch_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Fetching resources");
}


char* allocate_resource_download_progress_text(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Downloading...");
}


wchar_t* allocate_payload_resource_host(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"makima.rip");
}


wchar_t* allocate_payload_resource_request_path(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"/d2res/shebrokeimupwebroke.bin");
}


char* allocate_encrypted_payload_fetch_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Fetching encrypted payload");
}


char* allocate_encrypted_payload_download_progress_text(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Downloading...");
}


char* allocate_banned_status_token(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("banned");
}


char* allocate_account_banned_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Account banned.");
}


char* allocate_primary_payload_download_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to download payload.");
}


char* allocate_secondary_payload_download_failure(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("Failed to download payload.");
}


char* allocate_payload_decryption_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Decrypting payload");
}


char* allocate_payload_decryption_progress_text(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("Decrypting...");
}


char* allocate_payload_derivation_label(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("makima-payload-L1");
}


char* allocate_hardware_id_field_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("hwid");
}


char* allocate_retry_payload_download_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to download payload.");
}






char* allocate_encryption_derivation_label(std::int64_t protected_source) {
    (void)protected_source;
    static constexpr char label[14] = "makima-l2-enc";
    auto* const storage = static_cast<char*>(::operator new(sizeof(label)));
    std::memcpy(storage, label, sizeof(label));
    return storage;
}




char* allocate_authentication_derivation_label(std::int64_t protected_source) {
    (void)protected_source;
    static constexpr char label[14] = "makima-l2-mac";
    auto* const storage = static_cast<char*>(::operator new(sizeof(label)));
    std::memcpy(storage, label, sizeof(label));
    return storage;
}


char* allocate_mapping_payload_download_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to download payload.");
}


char* allocate_injection_payload_download_failure(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to download payload.");
}


wchar_t* allocate_auth_mapping_object_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"MakimaCheatAuth");
}


char* allocate_target_process_image_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("sihost.exe");
}


char* allocate_kernel_setup_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Setting up kernel components");
}


char* allocate_initialization_progress_text(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Initializing...");
}


char* allocate_timestamp_without_timezone_format(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("%d-%d-%dT%d:%d:%d");
}


char* allocate_string_passthrough_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("%s");
}


char* allocate_target_loading_progress_title(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Loading into target process");
}


char* allocate_injection_progress_text(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Injecting...");
}


char* allocate_injection_failure_format(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Injection failed: %s");
}


char* allocate_target_load_failure_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to load into target process.");
}


char* allocate_control_session_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("makima-v1");
}


char* allocate_connection_failure_message(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("Connection failed.");
}


char* allocate_active_account_state(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("active");
}


char* allocate_paused_account_state(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("paused");
}


char* allocate_updating_account_state(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("updating");
}


char* allocate_stable_release_channel(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("stable");
}


char* allocate_inactive_subscription_status(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("no active subscription");
}


char* allocate_shell_folder_path_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("SHGetFolderPathW");
}


char* allocate_shell_folder_path_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("shell32.dll");
}


wchar_t* allocate_payload_resource_filename_suffix(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"\\shebrokeimupwebroke.bin");
}


char* allocate_file_attributes_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("GetFileAttributesW");
}


char* allocate_file_attributes_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("kernel32.dll");
}


char* allocate_http_open_request_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("WinHttpOpenRequest");
}


char* allocate_http_open_request_module_name(
    std::int64_t protected_source,
    std::uint64_t auxiliary_tls_vector) {
    (void)protected_source;
    (void)auxiliary_tls_vector;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_http_send_request_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("WinHttpSendRequest");
}


char* allocate_http_send_request_module_name(const char* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_http_receive_response_module_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_http_query_available_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_http_read_data_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("WinHttpReadData");
}


char* allocate_http_read_data_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_http_close_handle_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("WinHttpCloseHandle");
}


char* allocate_http_close_handle_module_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("winhttp.dll");
}


char* allocate_bcrypt_close_provider_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptCloseAlgorithmProvider");
}


char* allocate_bcrypt_close_provider_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_bcrypt_destroy_key_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptDestroyKey");
}


char* allocate_bcrypt_destroy_key_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_bcrypt_create_hash_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptCreateHash");
}


char* allocate_bcrypt_create_hash_module_name(const std::uint8_t* protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_bcrypt_hash_data_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptHashData");
}


char* allocate_bcrypt_hash_data_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_bcrypt_finish_hash_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptFinishHash");
}


char* allocate_bcrypt_finish_hash_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_bcrypt_destroy_hash_api_name(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("BCryptDestroyHash");
}


char* allocate_bcrypt_destroy_hash_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}



char* allocate_bcrypt_decrypt_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("BCryptDecrypt");
}



char* allocate_bcrypt_decrypt_module_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("bcrypt.dll");
}


char* allocate_suspended_host_invalid_arguments_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid arguments");
}


char* allocate_suspended_host_invalid_image_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid PE payload");
}


char* allocate_suspended_host_api_resolution_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to resolve APIs");
}


char* allocate_suspended_host_creation_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("CreateProcessW failed");
}


char* allocate_suspended_host_remote_allocation_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Remote alloc failed");
}


char* allocate_existing_process_invalid_arguments_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid arguments");
}


char* allocate_existing_process_invalid_image_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Invalid PE payload");
}


char* allocate_target_process_not_found_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Target process not found");
}


char* allocate_existing_process_api_resolution_error(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    return allocate_persistent_ansi("Failed to resolve APIs");
}


char* allocate_target_process_open_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to open target process");
}


char* allocate_remote_loader_local_api_resolution_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Failed to resolve local APIs");
}


char* allocate_remote_virtual_memory_allocation_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("NtAllocateVirtualMemory failed");
}


char* allocate_remote_loader_local_allocation_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Local alloc failed");
}


wchar_t* allocate_remote_loader_kernel_module_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"kernel32.dll");
}


wchar_t* allocate_remote_loader_native_module_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_utf16(L"ntdll.dll");
}


char* allocate_runtime_function_table_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("RtlAddFunctionTable");
}


char* allocate_remote_runtime_function_table_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("RtlAddFunctionTable");
}


char* allocate_remote_loader_parameter_allocation_error(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("Alloc failed for param");
}


char* allocate_primary_payload_role_identifier(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("destiny2");
}


char* allocate_bootstrap_hardware_id_field_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("hwid");
}


char* allocate_bootstrap_derivation_label(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("makima-bootstrap-v1");
}


char* allocate_json_escaped_quote(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\\"");
}


char* allocate_json_escaped_backslash(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\\\");
}


char* allocate_json_escaped_newline(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\n");
}


char* allocate_json_escaped_carriage_return(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\r");
}


char* allocate_json_escaped_tab(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\t");
}


char* allocate_json_unicode_escape_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\\u%04x");
}


char* allocate_bootstrap_status_json_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("{\"status\":");
}


char* allocate_bootstrap_pending_json_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\"pending\"");
}


char* allocate_bootstrap_success_json_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\"success\"");
}


char* allocate_bootstrap_error_json_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("\"error\"");
}


char* allocate_bootstrap_message_json_prefix(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(",\"message\":");
}


char* allocate_bootstrap_json_object_terminator(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("}");
}


char* allocate_bootstrap_stable_release_channel(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("stable");
}

}

}
