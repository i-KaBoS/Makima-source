#include "makima/application/identity.hpp"

#include "makima/application/common.hpp"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#endif

#include <stdexcept>
#include <array>
#include <cstdio>

namespace makima::network::session {

bool write_current_user_sid_utf8(char* destination, int capacity) noexcept {



#ifdef _WIN32
    if (destination == nullptr || capacity <= 0) {
        return false;
    }

    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) == FALSE) {
        return false;
    }

    DWORD token_bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &token_bytes);
    if (token_bytes == 0) {
        CloseHandle(token);
        return false;
    }

    HANDLE process_heap = GetProcessHeap();
    void* token_buffer = process_heap != nullptr
        ? HeapAlloc(process_heap, 0, token_bytes)
        : nullptr;
    if (token_buffer == nullptr) {
        CloseHandle(token);
        return false;
    }

    bool converted = false;
    if (GetTokenInformation(token, TokenUser, token_buffer, token_bytes, &token_bytes) != FALSE) {
        const auto* token_user = static_cast<const TOKEN_USER*>(token_buffer);
        LPWSTR string_sid = nullptr;
        if (ConvertSidToStringSidW(token_user->User.Sid, &string_sid) != FALSE) {
            converted = WideCharToMultiByte(
                CP_UTF8,
                0,
                string_sid,
                -1,
                destination,
                capacity,
                nullptr,
                nullptr) != 0;
            LocalFree(string_sid);
        }
    }

    HeapFree(process_heap, 0, token_buffer);
    CloseHandle(token);
    return converted;
#else
    (void)destination;
    (void)capacity;
    return false;
#endif
}

}

namespace makima::application {

std::string WindowsHardwareIdentity::current_user_sid() const {

#ifdef _WIN32
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        throw ApplicationError("OpenProcessToken failed");
    struct HandleCloser {
        HANDLE value;
        ~HandleCloser() { if (value) CloseHandle(value); }
    } token_guard{token};

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || size == 0)
        throw ApplicationError("GetTokenInformation did not report a SID buffer size");
    Bytes buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size))
        throw ApplicationError("GetTokenInformation failed");

    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    LPWSTR wide_sid = nullptr;
    if (!ConvertSidToStringSidW(user->User.Sid, &wide_sid))
        throw ApplicationError("ConvertSidToStringSidW failed");
    struct LocalMemoryCloser {
        HLOCAL value;
        ~LocalMemoryCloser() { if (value) LocalFree(value); }
    } sid_guard{wide_sid};

    const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_sid, -1, nullptr, 0, nullptr, nullptr);
    if (length <= 1) throw ApplicationError("Windows returned an invalid SID");
    std::string result(static_cast<std::size_t>(length), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_sid, -1,
            result.data(), length, nullptr, nullptr) == 0)
        throw ApplicationError("SID UTF-8 conversion failed");
    result.resize(static_cast<std::size_t>(length - 1));
    if (!result.starts_with("S-")) throw ApplicationError("Windows returned an invalid SID");
    return result;
#else
    throw ApplicationError("Windows is required for SID detection");
#endif
}

std::string resolve_hwid(const IHardwareIdentity& identity) noexcept {
    try {
        std::string sid = identity.current_user_sid();
        return sid.starts_with("S-") ? sid : "anon";
    } catch (const std::exception&) {
        return "anon";
    }
}

std::string format_protocol_identifier(
    const std::array<std::uint8_t, 16>& identifier,
    std::uint32_t suffix) {
    constexpr char identifier_format[] =
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X%X";
    std::array<char, 48> output{};
    std::snprintf(output.data(), output.size(), identifier_format,
        identifier[0], identifier[1], identifier[2], identifier[3],
        identifier[4], identifier[5], identifier[6], identifier[7],
        identifier[8], identifier[9], identifier[10], identifier[11],
        identifier[12], identifier[13], identifier[14], identifier[15], suffix);
    return output.data();
}

}
