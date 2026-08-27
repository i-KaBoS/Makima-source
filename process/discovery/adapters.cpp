#include "process/discovery/discovery.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstring>
#include <cwchar>
#include <new>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace makima::process::discovery {





void install_discovery_notification(
    DiscoveryWorkerCallback callback,
    std::uintptr_t context) noexcept {
    auto& runtime = discovery_worker_runtime();
    if (runtime.worker_thread == nullptr || runtime.dispatching) return;
    publish_discovery_worker_notification(callback, context);
}




[[nodiscard]] bool discovery_notification_is_pending() noexcept {
    return discovery_worker_runtime().dispatching;
}



[[nodiscard]] std::vector<DWORD> snapshot_live_process_ids() {
    std::vector<DWORD> process_ids;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return process_ids;
    PROCESSENTRY32W entry{sizeof(entry)};
    if (Process32FirstW(snapshot, &entry)) {
        do {
            process_ids.push_back(entry.th32ProcessID);
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return process_ids;
}



[[nodiscard]] DWORD find_live_process_by_image(
    std::wstring_view image_name) noexcept {
    if (image_name.empty()) return 0;
    const std::wstring owned_name{image_name};
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    DWORD result = 0;
    PROCESSENTRY32W entry{sizeof(entry)};
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, owned_name.c_str()) == 0) {
                result = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}



[[nodiscard]] bool fill_discovery_nonce(
    void* context,
    void* output,
    std::size_t output_size) noexcept {
    (void)context;
    BCRYPT_ALG_HANDLE provider{};
    const NTSTATUS opened = BCryptOpenAlgorithmProvider(
        &provider, BCRYPT_RNG_ALGORITHM, nullptr, 0);
    if (opened != 0) return false;
    const NTSTATUS generated = BCryptGenRandom(
        provider,
        static_cast<PUCHAR>(output),
        static_cast<ULONG>(output_size & 0xffffffffU),
        0);
    BCryptCloseAlgorithmProvider(provider, 0);
    return generated == 0;
}



char* allocate_kernel32_for_create_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr std::string_view value{"kernel32.dll"};
    auto* output = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return output;
}




void format_discovery_message(
    wchar_t* destination,
    const wchar_t* format,
    ...) noexcept {
    std::va_list arguments;
    va_start(arguments, format);
    static_cast<void>(vswprintf_s(destination, 0x108, format, arguments));
    va_end(arguments);
}

}
