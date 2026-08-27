#include "kernel/symbols/symbols.hpp"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>
#include <array>
#include <limits>

namespace makima::kernel::symbols {
namespace {

struct InternetHandle final {
    HINTERNET value{};
    ~InternetHandle() {
        if (value != nullptr) {
            WinHttpCloseHandle(value);
        }
    }
    InternetHandle() = default;
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
};

}

std::uintptr_t SymbolResolver::address_of(
    std::string_view symbol_name) const noexcept {
    return resolve_public_symbol(*this, symbol_name);
}





std::uint32_t consume_live_kernel_and_pdb_data(
    SymbolResolver& resolver,
    KernelModuleState* const* module) {
    resolver.loaded_kernel_base = (*module)->ntoskrnl_base;
    if (resolver.loaded_kernel_base == 0) {
        resolver.error = "kernel_base is zero";
        return 0;
    }

    CodeViewIdentity identity;
    if (!read_codeview_from_live_kernel(
            module,
            resolver.loaded_kernel_base,
            identity,
            resolver.error)) {
        return 0;
    }
    return static_cast<std::uint32_t>(
        download_and_parse_matching_pdb(resolver, identity));
}





std::uint32_t map_ntoskrnl_for_symbol_resolution(
    SymbolResolver& resolver,
    std::uintptr_t loaded_kernel_base,
    const wchar_t* installed_image) {
    resolver.loaded_kernel_base = loaded_kernel_base;
    if (loaded_kernel_base == 0) {
        resolver.error = "kernel_base is zero";
        return 0;
    }

    static constexpr wchar_t default_image[] = L"ntoskrnl.exe";
    const wchar_t* const image_path = installed_image == nullptr
        ? default_image
        : installed_image;

    const HMODULE mapped = LoadLibraryExW(
        image_path,
        nullptr,
        DONT_RESOLVE_DLL_REFERENCES);
    if (mapped == nullptr) {
        resolver.error = "LoadLibraryEx failed";
        return 0;
    }

    const auto live_base = resolver.loaded_kernel_base;
    resolver.loaded_kernel_base = reinterpret_cast<std::uintptr_t>(mapped);
    const LoadedImageView mapped_view{
        resolver.loaded_kernel_base,
        resolver.loaded_kernel_base};
    CodeViewIdentity identity;
    const bool parsed = read_codeview_from_loaded_module(
        mapped_view,
        resolver.loaded_kernel_base,
        identity,
        resolver.error);
    resolver.loaded_kernel_base = live_base;
    FreeLibrary(mapped);
    return parsed
        ? static_cast<std::uint32_t>(
              download_and_parse_matching_pdb(resolver, identity))
        : 0U;
}



std::uint64_t microsoft_symbol_server_download(
    const std::wstring& request_path,
    std::vector<std::byte>& destination,
    std::string& error) noexcept {
    constexpr std::size_t maximum_pdb_size = 0x100000;
    destination.clear();
    error.clear();
    InternetHandle session;
    InternetHandle connection;
    InternetHandle request;
    session.value = WinHttpOpen(
        L"Microsoft-Symbol-Server/10.0.0.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);
    if (session.value == nullptr) {
        error = "WinHttpOpen failed";
        return false;
    }
    static const wchar_t* const symbol_server_host =
        allocate_microsoft_symbol_server_host_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DA444ull));
    connection.value = WinHttpConnect(
        session.value, symbol_server_host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (connection.value == nullptr) {
        static const char* const connect_failure =
            allocate_winhttp_connect_failure_message(
                reinterpret_cast<const std::uint8_t*>(0x1414DA46Cull));
        error = connect_failure;
        return false;
    }
    if (request_path.empty()) {
        error = "symbol-server path is empty";
        return 0;
    }
    request.value = WinHttpOpenRequest(
        connection.value,
        L"GET",
        request_path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (request.value == nullptr) {
        error = "WinHttpOpenRequest failed";
        return false;
    }
    if (!WinHttpSendRequest(
            request.value,
            WINHTTP_NO_ADDITIONAL_HEADERS,
            0,
            WINHTTP_NO_REQUEST_DATA,
            0,
            0,
            0)) {
        error = "WinHttpSendRequest failed";
        return false;
    }
    if (!WinHttpReceiveResponse(request.value, nullptr)) {
        error = "WinHttpReceiveResponse failed";
        return false;
    }
    DWORD status{};
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(
            request.value,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &status,
            &status_size,
            WINHTTP_NO_HEADER_INDEX) ||
        status != HTTP_STATUS_OK) {
        error = "HTTP " + std::to_string(status);
        return false;
    }
    DWORD content_length{};
    DWORD content_length_size = sizeof(content_length);
    if (WinHttpQueryHeaders(
            request.value,
            WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &content_length,
            &content_length_size,
            WINHTTP_NO_HEADER_INDEX)) {
        if (content_length == 0 || content_length > maximum_pdb_size) {
            error = "Content-Length out of range";
            return false;
        }
        destination.reserve(content_length);
    }
    try {
        std::array<std::byte, 0x10000> chunk{};
        for (;;) {
            DWORD available{};
            if (!WinHttpQueryDataAvailable(request.value, &available)) {
                error = "QueryDataAvailable failed";
                destination.clear();
                return false;
            }
            if (available == 0) {
                break;
            }
            while (available != 0) {
                const DWORD requested = std::min<DWORD>(
                    available, static_cast<DWORD>(chunk.size()));
                DWORD received{};
                if (!WinHttpReadData(
                        request.value, chunk.data(), requested, &received)) {
                    error = "WinHttpReadData failed";
                    destination.clear();
                    return false;
                }
                if (received == 0) {
                    break;
                }
                if (destination.size() + received > maximum_pdb_size) {
                    error = "exceeded max PDB size";
                    destination.clear();
                    return false;
                }
                destination.insert(
                    destination.end(), chunk.begin(), chunk.begin() + received);
                available -= std::min(available, received);
            }
        }
    } catch (...) {
        error = "PDB allocation failed";
        destination.clear();
        return false;
    }
    if (destination.size() < 0x38) {
        error = "downloaded body too small";
        destination.clear();
        return false;
    }
    return true;
}

}
