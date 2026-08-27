#include "makima/platform/target_discovery.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <limits>
#include <string>
#include <thread>
#include <utility>

namespace makima::platform {
namespace {

class SnapshotHandle final {
public:
    explicit SnapshotHandle(HANDLE value) noexcept : value_(value) {}
    ~SnapshotHandle() {
        if (value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }
    SnapshotHandle(const SnapshotHandle&) = delete;
    SnapshotHandle& operator=(const SnapshotHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE value_{INVALID_HANDLE_VALUE};
};

std::string normalize_slug(std::string_view slug) {
    std::string result(slug);
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

std::string wide_to_utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const auto size = WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(size), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        WC_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        size,
        nullptr,
        nullptr);
    return result;
}

std::optional<application::TargetProcess> find_process(
    const std::vector<std::wstring>& image_names) {
    SnapshotHandle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snapshot) {
        throw application::ApplicationError("CreateToolhelp32Snapshot failed during target discovery");
    }
    PROCESSENTRY32W process{};
    process.dwSize = sizeof(process);
    if (Process32FirstW(snapshot.get(), &process) == FALSE) {
        return std::nullopt;
    }
    do {
        const auto match = std::find_if(
            image_names.begin(),
            image_names.end(),
            [&](const std::wstring& candidate) {
                return _wcsicmp(candidate.c_str(), process.szExeFile) == 0;
            });
        if (match != image_names.end()) {
            return application::TargetProcess{
                process.th32ProcessID,
                wide_to_utf8(process.szExeFile),
            };
        }
    } while (Process32NextW(snapshot.get(), &process) != FALSE);
    return std::nullopt;
}

}

ToolhelpTargetDiscovery::ToolhelpTargetDiscovery(ProductImages product_images)
    : product_images_(std::move(product_images)) {}

ToolhelpTargetDiscovery::ProductImages ToolhelpTargetDiscovery::default_product_images() {
    return {
        {"*", {L"sihost.exe"}},
    };
}

std::optional<application::TargetProcess> ToolhelpTargetDiscovery::wait_for_target(
    std::string_view product_slug,
    std::chrono::milliseconds timeout) {
    auto product = product_images_.find(normalize_slug(product_slug));
    if (product == product_images_.end()) product = product_images_.find("*");
    if (product == product_images_.end() || product->second.empty()) {
        return std::nullopt;
    }
    const auto bounded_timeout = std::max(timeout, std::chrono::milliseconds::zero());
    const auto deadline = std::chrono::steady_clock::now() + bounded_timeout;
    for (;;) {
        if (auto process = find_process(product->second)) {
            return process;
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            return std::nullopt;
        }
        std::this_thread::sleep_for(std::min(std::chrono::milliseconds{250},
                                             std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)));
    }
}

}
