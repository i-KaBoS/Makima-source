#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"
#include "process/pe_mapping/pe_mapping.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <exception>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

namespace makima::payload::crypto {
namespace {
template <typename T>
const T* object_at(const detail::PeImageView& image, std::size_t offset) noexcept {
    if (offset > image.size || image.size - offset < sizeof(T)) return nullptr;
    return reinterpret_cast<const T*>(image.bytes + offset);
}

}




void resize_zero_filled_crypto_storage(
    std::vector<std::byte>& buffer,
    std::size_t requested_size) {
    buffer.resize(requested_size, std::byte{});
}

namespace detail {



[[nodiscard]] PeImageView inspect_pe_image(
    const void* image_bytes,
    std::size_t image_size) noexcept {
    PeImageView view{};
    view.bytes = static_cast<const std::byte*>(image_bytes);
    view.size = image_size;
    if (image_bytes == nullptr || image_size < 0x40) return view;
    const auto* dos = object_at<IMAGE_DOS_HEADER>(view, 0);
    if (dos == nullptr || dos->e_magic != IMAGE_DOS_SIGNATURE ||
        dos->e_lfanew < 0) {
        return view;
    }
    const auto nt_offset = static_cast<std::size_t>(dos->e_lfanew);

    if (nt_offset > image_size || image_size - nt_offset < 0x108) return view;
    view.dos_header = dos;
    view.nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        view.bytes + nt_offset);
    view.valid = view.nt_headers->Signature == IMAGE_NT_SIGNATURE;
    return view;
}


[[nodiscard]] std::uint32_t pe_virtual_image_size(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.SizeOfImage : 0U;
}


[[nodiscard]] std::uint64_t pe_preferred_image_base(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.ImageBase : 0U;
}


[[nodiscard]] std::uint32_t pe_entry_point_rva(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.AddressOfEntryPoint : 0U;
}


[[nodiscard]] std::uint32_t pe_header_copy_size(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.SizeOfHeaders : 0U;
}


[[nodiscard]] std::uint64_t pe_stack_reserve_size(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.SizeOfStackReserve : 0U;
}


[[nodiscard]] std::uint64_t pe_stack_commit_size(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->OptionalHeader.SizeOfStackCommit : 0U;
}


[[nodiscard]] std::uint16_t pe_section_count(
    const PeImageView& image) noexcept {
    return image.valid ? image.nt_headers->FileHeader.NumberOfSections : 0U;
}



void read_pe_section(
    const PeImageView& image,
    MappedPeSection& destination,
    int index) noexcept {
    destination = {};
    if (!image.valid || index < 0 ||
        static_cast<unsigned>(index) >= image.nt_headers->FileHeader.NumberOfSections) {
        return;
    }
    const auto* section = IMAGE_FIRST_SECTION(image.nt_headers) + index;
    const auto* first = reinterpret_cast<const std::byte*>(section);
    if (first < image.bytes) {
        return;
    }
    const auto offset = static_cast<std::size_t>(first - image.bytes);
    if (offset > image.size || image.size - offset < sizeof(*section)) {
        return;
    }
    destination.virtual_size = section->Misc.VirtualSize;
    destination.virtual_address = section->VirtualAddress;
    destination.raw_data_size = section->SizeOfRawData;
    destination.raw_data_offset = section->PointerToRawData;
    destination.characteristics = section->Characteristics;
    std::memcpy(destination.name.data(), section->Name, destination.name.size());
}

}

std::uint32_t map_payload_into_process(
    char* error_buffer,
    HANDLE process,
    const void* payload,
    std::size_t payload_size) noexcept {
    if (error_buffer != nullptr) {
        *error_buffer = '\0';
    }
    if (error_buffer == nullptr || process == nullptr || payload == nullptr ||
        payload_size == 0) {
        if (error_buffer != nullptr) {
            strcpy_s(error_buffer, 0x100, "Invalid arguments");
        }
        return 0;
    }

    const detail::PeImageView image =
        detail::inspect_pe_image(payload, payload_size);
    if (!image.valid || detail::pe_virtual_image_size(image) == 0 ||
        detail::pe_header_copy_size(image) == 0) {
        strcpy_s(error_buffer, 0x100, "Invalid PE payload");
        return 0;
    }



    const auto preferred_base = detail::pe_preferred_image_base(image);
    const auto entry_point = detail::pe_entry_point_rva(image);
    const auto stack_reserve = detail::pe_stack_reserve_size(image);
    const auto stack_commit = detail::pe_stack_commit_size(image);
    (void)preferred_base;
    (void)entry_point;
    (void)stack_reserve;
    (void)stack_commit;
    for (std::uint16_t index = 0; index < detail::pe_section_count(image); ++index) {
        detail::MappedPeSection section{};
        detail::read_pe_section(image, section, index);
    }

    const DWORD process_id = GetProcessId(process);
    if (process_id == 0) {
        strcpy_s(error_buffer, 0x100, "Failed to query target process");
        return 0;
    }

    try {
        const auto* first = static_cast<const std::uint8_t*>(payload);
        const auto result = ::makima::process::pe_mapping::manual_map_pe_dll(
            process_id, std::span<const std::uint8_t>{first, payload_size});
        return result.image_base == 0 ? 0U : 1U;
    } catch (const std::exception& error) {
        strncpy_s(error_buffer, 0x100, error.what(), _TRUNCATE);
        return 0;
    } catch (...) {
        strcpy_s(error_buffer, 0x100, "Failed to map payload");
        return 0;
    }
}




const char* secondary_payload_role_identifier(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    auto* output = static_cast<char*>(::operator new(9U));
    std::memcpy(output, "warframe", 9U);
    return output;
}



EcdhSession* initialize_empty_ecdh_session(EcdhSession* session) noexcept {
    std::memset(session, 0, sizeof(*session));
    return session;
}

namespace detail {

char* allocate_narrow_api_token(std::string_view token) {
    auto* output = static_cast<char*>(::operator new(token.size() + 1U));
    std::memcpy(output, token.data(), token.size());
    output[token.size()] = '\0';
    return output;
}

wchar_t* allocate_wide_api_token(std::wstring_view token) {
    auto* output = static_cast<wchar_t*>(
        ::operator new((token.size() + 1U) * sizeof(wchar_t)));
    std::memcpy(output, token.data(), token.size() * sizeof(wchar_t));
    output[token.size()] = L'\0';
    return output;
}



char* allocate_payload_download_failure_for_status_record(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Failed to download payload.");
}



char* allocate_target_load_failure_for_status_record(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Failed to load into target process.");
}



char* allocate_undetected_account_state(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("undetected");
}



char* allocate_not_logged_in_message(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Not logged in.");
}



char* allocate_not_connected_message(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Not connected.");
}



char* allocate_server_connection_failure_message(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Failed to connect to servers.");
}



char* allocate_winhttp_connect_api_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("WinHttpConnect");
}


char* allocate_winhttp_module_for_connect(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("winhttp.dll");
}



char* allocate_winhttp_receive_response_api_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("WinHttpReceiveResponse");
}



char* allocate_winhttp_query_available_api_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("WinHttpQueryDataAvailable");
}



char* allocate_connection_progress_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("Connecting...");
}



wchar_t* allocate_http_request_verb(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_api_token(L"GET");
}



char* allocate_alternate_derivation_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_narrow_api_token("makima-payload-L2");
}


const char* connecting_progress_text() {
    static const char* const value = allocate_connection_progress_value(
        reinterpret_cast<const std::uint8_t*>(0x1414D8400ull));
    return value;
}


const wchar_t* http_get_method() {
    static const wchar_t* const value = allocate_http_request_verb(
        reinterpret_cast<const std::uint16_t*>(0x1414D84F0ull));
    return value;
}


const char* alternate_derivation_label() {
    static const char* const value = allocate_alternate_derivation_value(
        reinterpret_cast<const std::uint8_t*>(0x1414D85B5ull));
    return value;
}



const char* payload_download_failure_status_record() {
    static const char* value = allocate_payload_download_failure_for_status_record(reinterpret_cast<const std::uint8_t*>(0X1414D8603ull));
    return value;
}



const char* target_load_failure_status_record() {
    static const char* value = allocate_target_load_failure_for_status_record(reinterpret_cast<const std::uint8_t*>(0X1414D86CEull));
    return value;
}



void compute_hmac_sha256(
    const std::byte* key,
    std::size_t key_size,
    const std::byte* input,
    std::size_t input_size,
    std::byte* digest) noexcept {
    if ((key == nullptr && key_size != 0) ||
        (input == nullptr && input_size != 0) || digest == nullptr ||
        key_size > std::numeric_limits<ULONG>::max() ||
        input_size > std::numeric_limits<ULONG>::max()) {
        if (digest != nullptr) {
            SecureZeroMemory(digest, 32);
        }
        return;
    }

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    std::vector<std::byte> hash_object;
    bool succeeded = false;
    try {
        ULONG object_size{};
        ULONG written{};
        if (BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) >= 0 &&
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(&object_size),
                sizeof(object_size),
                &written,
                0) >= 0 &&
            written == sizeof(object_size)) {
            hash_object.resize(object_size);
            if (BCryptCreateHash(
                    algorithm,
                    &hash,
                    reinterpret_cast<PUCHAR>(hash_object.data()),
                    object_size,
                    reinterpret_cast<PUCHAR>(
                        const_cast<std::byte*>(key)),
                    static_cast<ULONG>(key_size),
                    0) >= 0 &&
                BCryptHashData(
                    hash,
                    reinterpret_cast<PUCHAR>(
                        const_cast<std::byte*>(input)),
                    static_cast<ULONG>(input_size),
                    0) >= 0 &&
                BCryptFinishHash(
                    hash,
                    reinterpret_cast<PUCHAR>(digest),
                    32,
                    0) >= 0) {
                succeeded = true;
            }
        }
    } catch (...) {
        succeeded = false;
    }

    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    if (!hash_object.empty()) {
        SecureZeroMemory(hash_object.data(), hash_object.size());
    }
    if (!succeeded) {
        SecureZeroMemory(digest, 32);
    }
}






const char* discord_login_failure() {
    static const char* const value = allocate_discord_login_failure(0X1414D8194ll);
    return value;
}


const char* login_invalid_server_response() {
    static const char* const value = allocate_login_invalid_server_response(0X1414D81ABll);
    return value;
}


const char* sync_invalid_server_response() {
    static const char* const value = allocate_sync_invalid_server_response(0X1414D81C5ll);
    return value;
}


const char* clock_skew_guidance() {
    static const char* const value = allocate_clock_skew_guidance(0X1414D81DFll);
    return value;
}


const char* clock_skew_code() {
    static const char* const value = allocate_clock_skew_code(reinterpret_cast<const std::uint8_t*>(0X1414D8262ull));
    return value;
}


const char* websocket_protocol_label() {
    static const char* const value = allocate_websocket_protocol_label(reinterpret_cast<const std::uint8_t*>(0X1414D826Eull));
    return value;
}


const char* websocket_transport_name() {
    static const char* const value = allocate_websocket_transport_name(reinterpret_cast<const std::uint8_t*>(0X1414D827Cull));
    return value;
}


const char* detection_state_token() {
    static const char* const value = allocate_detection_state_token(reinterpret_cast<const std::uint8_t*>(0X1414D82ADull));
    return value;
}


const char* subscription_required_message() {
    static const char* const value = allocate_subscription_required_message(0X1414D8335ll);
    return value;
}


const char* no_payload_code() {
    static const char* const value = allocate_no_payload_code(reinterpret_cast<const std::uint8_t*>(0X1414D835Full));
    return value;
}


const char* branch_has_no_payload_message() {
    static const char* const value = allocate_branch_has_no_payload_message(0X1414D836Bll, 4);
    return value;
}


const char* session_creation_failed_message() {
    static const char* const value = allocate_session_creation_failed_message(0X1414D8392ll);
    return value;
}


const char* invalid_session_response_message() {
    static const char* const value = allocate_invalid_session_response_message(0X1414D83CCll);
    return value;
}


const char* secure_session_progress_title() {
    static const char* const value = allocate_secure_session_progress_title(0X1414D83E7ll);
    return value;
}


const char* dma_dependency_download_failure() {
    static const char* const value = allocate_dma_dependency_download_failure(0X1414D840Fll);
    return value;
}


const char* payload_product_name() {
    static const char* const value = allocate_payload_product_name(reinterpret_cast<const std::uint8_t*>(0X1414D8435ull));
    return value;
}


const char* resource_fetch_progress_title() {
    static const char* const value = allocate_resource_fetch_progress_title(0X1414D8474ll);
    return value;
}


const char* resource_download_progress_text() {
    static const char* const value = allocate_resource_download_progress_text(0X1414D8488ll);
    return value;
}


const wchar_t* payload_resource_host() {
    static const wchar_t* const value = allocate_payload_resource_host(reinterpret_cast<const std::uint16_t*>(0X1414D8498ull));
    return value;
}


const wchar_t* payload_resource_request_path() {
    static const wchar_t* const value = allocate_payload_resource_request_path(reinterpret_cast<const std::uint16_t*>(0X1414D84B0ull));
    return value;
}


const char* encrypted_payload_fetch_progress_title() {
    static const char* const value = allocate_encrypted_payload_fetch_progress_title(0X1414D84FAll);
    return value;
}


const char* encrypted_payload_download_progress_text() {
    static const char* const value = allocate_encrypted_payload_download_progress_text(0X1414D8516ll);
    return value;
}


const char* banned_status_token() {
    static const char* const value = allocate_banned_status_token(reinterpret_cast<const std::uint8_t*>(0X1414D8526ull));
    return value;
}


const char* account_banned_message() {
    static const char* const value = allocate_account_banned_message(0X1414D852Ell);
    return value;
}


const char* primary_payload_download_failure() {
    static const char* const value = allocate_primary_payload_download_failure(0X1414D853Fll);
    return value;
}


const char* secondary_payload_download_failure() {
    static const char* const value = allocate_secondary_payload_download_failure(0X1414D855Cll, 4);
    return value;
}


const char* payload_decryption_progress_title() {
    static const char* const value = allocate_payload_decryption_progress_title(0X1414D8579ll);
    return value;
}


const char* payload_decryption_progress_text() {
    static const char* const value = allocate_payload_decryption_progress_text(0X1414D858Dll, 4);
    return value;
}


const char* payload_derivation_label() {
    static const char* const value = allocate_payload_derivation_label(0X1414D859Cll);
    return value;
}


const char* hardware_id_field_name() {
    static const char* const value = allocate_hardware_id_field_name(reinterpret_cast<const std::uint8_t*>(0X1414D85AFull));
    return value;
}


const char* retry_payload_download_failure() {
    static const char* const value = allocate_retry_payload_download_failure(0X1414D85C8ll);
    return value;
}


const char* mapping_payload_download_failure() {
    static const char* const value = allocate_mapping_payload_download_failure(0X1414D8620ll);
    return value;
}


const char* injection_payload_download_failure() {
    static const char* const value = allocate_injection_payload_download_failure(0X1414D863Dll);
    return value;
}


const wchar_t* auth_mapping_object_name() {
    static const wchar_t* const value = allocate_auth_mapping_object_name(reinterpret_cast<const std::uint16_t*>(0X1414D865Aull));
    return value;
}


const char* target_process_image_name() {
    static const char* const value = allocate_target_process_image_name(reinterpret_cast<const std::uint8_t*>(0X1414D867Cull));
    return value;
}


const char* kernel_setup_progress_title() {
    static const char* const value = allocate_kernel_setup_progress_title(0X1414D8688ll);
    return value;
}


const char* initialization_progress_text() {
    static const char* const value = allocate_initialization_progress_text(0X1414D86A6ll);
    return value;
}


const char* timestamp_without_timezone_format() {
    static const char* const value = allocate_timestamp_without_timezone_format(0X1414D86B7ll);
    return value;
}


const char* string_passthrough_format() {
    static const char* const value = allocate_string_passthrough_format(reinterpret_cast<const std::uint8_t*>(0X1414D86CAull));
    return value;
}


const char* target_loading_progress_title() {
    static const char* const value = allocate_target_loading_progress_title(0X1414D86F3ll);
    return value;
}


const char* injection_progress_text() {
    static const char* const value = allocate_injection_progress_text(0X1414D8710ll);
    return value;
}


const char* injection_failure_format() {
    static const char* const value = allocate_injection_failure_format(0X1414D871Ell);
    return value;
}


const char* target_load_failure_message() {
    static const char* const value = allocate_target_load_failure_message(0X1414D8734ll);
    return value;
}


const char* control_session_label() {
    static const char* const value = allocate_control_session_label(reinterpret_cast<const std::uint8_t*>(0X1414DB257ull));
    return value;
}

}

}
