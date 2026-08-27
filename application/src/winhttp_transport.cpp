#include "makima/application/winhttp_transport.hpp"
#include "makima/application/winhttp_certificate.hpp"

#include <algorithm>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#endif

namespace makima::application {
namespace {

constexpr wchar_t browser_user_agent[] =
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    L"Chrome/131.0.0.0 Safari/537.36";

#ifdef _WIN32
std::wstring widen(std::string_view text) {
    if (text.empty()) return {};
    const int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0);
    if (count <= 0) throw ApplicationError("URL is not valid UTF-8");
    std::wstring result(static_cast<std::size_t>(count), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), result.data(), count) != count)
        throw ApplicationError("URL UTF-8 conversion failed");
    return result;
}

std::string narrow(std::wstring_view text) {
    if (text.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
        static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string result(static_cast<std::size_t>(count), '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), result.data(), count, nullptr, nullptr) != count)
        return {};
    return result;
}

class InternetHandle {
public:
    explicit InternetHandle(HINTERNET value = nullptr) : value_(value) {}
    ~InternetHandle() { if (value_) WinHttpCloseHandle(value_); }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
    operator HINTERNET() const noexcept { return value_; }
private:
    HINTERNET value_{};
};

std::optional<std::string> query_header(HINTERNET request, DWORD query) {
    DWORD bytes = 0;
    WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, nullptr, &bytes,
        WINHTTP_NO_HEADER_INDEX);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || bytes < sizeof(wchar_t)) return std::nullopt;
    std::wstring buffer(bytes / sizeof(wchar_t), L'\0');
    if (!WinHttpQueryHeaders(request, query, WINHTTP_HEADER_NAME_BY_INDEX, buffer.data(), &bytes,
            WINHTTP_NO_HEADER_INDEX)) return std::nullopt;
    buffer.resize(bytes / sizeof(wchar_t));
    while (!buffer.empty() && buffer.back() == L'\0') buffer.pop_back();
    return narrow(buffer);
}
#endif

}

HttpResponse WinHttpTransport::post(
    std::string_view url,
    std::span<const std::uint8_t> body,
    std::chrono::milliseconds timeout) {
#ifdef _WIN32

    if (body.size() > std::numeric_limits<DWORD>::max())
        throw ApplicationError("HTTP request body exceeds WinHTTP limits");
    constexpr std::string_view plain_http_prefix = "http://";
    const bool plain_http = url.starts_with(plain_http_prefix);
    std::wstring wide_url = widen(url);
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(wide_url.c_str(), static_cast<DWORD>(wide_url.size()), 0, &components))
        throw ApplicationError("WinHttpCrackUrl failed");
    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring path(components.lpszUrlPath, components.dwUrlPathLength);
    path.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    if (path.empty()) path = L"/";
    const bool secure = components.nScheme == INTERNET_SCHEME_HTTPS;
    if (!secure && !(plain_http && components.nScheme == INTERNET_SCHEME_HTTP))
        throw ApplicationError("unsupported URL scheme");

    InternetHandle session(WinHttpOpen(browser_user_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) throw ApplicationError("WinHttpOpen failed");
    const int timeout_ms = static_cast<int>(std::clamp<std::int64_t>(timeout.count(), 1, INT_MAX));
    if (!WinHttpSetTimeouts(session, timeout_ms, timeout_ms, timeout_ms, timeout_ms))
        throw ApplicationError("WinHttpSetTimeouts failed");
    InternetHandle connection(WinHttpConnect(session, host.c_str(), components.nPort, 0));
    if (!connection) throw ApplicationError("WinHttpConnect failed");
    const DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    InternetHandle request(WinHttpOpenRequest(connection, L"POST", path.c_str(), nullptr,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request) throw ApplicationError("WinHttpOpenRequest failed");
    constexpr wchar_t request_headers[] =
        L"Content-Type: application/octet-stream\r\n"
        L"Cache-Control: no-store\r\n";
    if (!WinHttpSendRequest(request, request_headers, static_cast<DWORD>(-1L),
            body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<std::uint8_t*>(body.data()),
            static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0))
        throw ApplicationError("WinHttpSendRequest failed");
    if (!WinHttpReceiveResponse(request, nullptr))
        throw ApplicationError("WinHttpReceiveResponse failed");
    if (secure) {
        const std::string expected_host = narrow(host);
        if (!verify_winhttp_server_certificate(request, expected_host))
            throw ApplicationError("server certificate validation failed");
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX))
        throw ApplicationError("cannot read HTTP status");
    HttpResponse response;
    response.status = static_cast<int>(status);
    if (auto value = query_header(request, WINHTTP_QUERY_CONTENT_TYPE))
        response.headers.emplace("Content-Type", std::move(*value));
    if (auto value = query_header(request, WINHTTP_QUERY_CONTENT_DISPOSITION))
        response.headers.emplace("Content-Disposition", std::move(*value));

    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request, &available))
            throw ApplicationError("WinHttpQueryDataAvailable failed");
        if (available == 0) break;
        const std::size_t start = response.body.size();
        response.body.resize(start + available);
        DWORD received = 0;
        if (!WinHttpReadData(request, response.body.data() + start, available, &received))
            throw ApplicationError("WinHttpReadData failed");
        response.body.resize(start + received);
        if (received == 0) break;
    }
    return response;
#else
    (void)url; (void)body; (void)timeout;
    throw ApplicationError("WinHTTP transport is only available on Windows");
#endif
}

}
