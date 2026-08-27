#include "process/pe_mapping/pe_mapping.hpp"

#include <algorithm>
#include <cwchar>
#include <optional>
#include <string>
#include <string_view>

namespace makima::process::pe_mapping {
namespace {

class UniqueHandle final {
public:
    explicit UniqueHandle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~UniqueHandle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            ::CloseHandle(value_);
        }
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }
private:
    HANDLE value_{};
};

}

FARPROC resolve_loaded_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    if (module_name == nullptr || symbol_name == nullptr) {
        return nullptr;
    }
    const HMODULE module = ::GetModuleHandleA(module_name);
    return module == nullptr ? nullptr : ::GetProcAddress(module, symbol_name);
}



FARPROC resolve_virtual_query_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}



std::wstring widen_process_name(std::string_view process_name) {
    std::wstring result;
    result.reserve(std::min<std::size_t>(process_name.size(), MAX_PATH - 1));
    for (const unsigned char character : process_name.substr(0, MAX_PATH - 1)) {
        result.push_back(static_cast<wchar_t>(character));
    }
    return result;
}




std::optional<ProcessMatch> find_process_by_name(std::wstring_view process_name) {
    if (process_name.empty()) {
        return std::nullopt;
    }
    const auto create_snapshot = resolve_create_toolhelp32_snapshot_api();
    const auto process_first = resolve_process32_first_api();
    const auto process_next = resolve_process32_next_api();
    UniqueHandle snapshot{create_snapshot(TH32CS_SNAPPROCESS, 0)};
    if (!snapshot) {
        return std::nullopt;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!process_first(snapshot.get(), &entry)) {
        return std::nullopt;
    }
    do {
        if (_wcsicmp(entry.szExeFile, std::wstring{process_name}.c_str()) != 0) {
            continue;
        }
        UniqueHandle process{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID)};
        BOOL wow64 = FALSE;
        if (process) {
            static_cast<void>(::IsWow64Process(process.get(), &wow64));
        }
        return ProcessMatch{entry.th32ProcessID, wow64 != FALSE};
    } while (process_next(snapshot.get(), &entry));
    return std::nullopt;
}


FARPROC resolve_snapshot_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}


FARPROC resolve_process_first_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}


FARPROC resolve_process_next_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}


FARPROC resolve_local_free_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}



FARPROC resolve_sleep_export(
    const char* module_name,
    const char* symbol_name) noexcept {
    return resolve_loaded_export(module_name, symbol_name);
}

std::optional<RemoteModule> find_remote_module(
    std::uint32_t process_id,
    std::wstring_view module_name) {
    UniqueHandle snapshot{::CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)};
    if (!snapshot) {
        return std::nullopt;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Module32FirstW(snapshot.get(), &entry)) {
        return std::nullopt;
    }
    do {
        if (_wcsicmp(entry.szModule, std::wstring{module_name}.c_str()) == 0) {
            return RemoteModule{
                reinterpret_cast<VirtualAddress>(entry.modBaseAddr),
                entry.modBaseSize,
                entry.szModule,
                entry.szExePath,
            };
        }
    } while (::Module32NextW(snapshot.get(), &entry));
    return std::nullopt;
}


std::optional<RemoteModule> find_remote_module_by_index(
    std::uint32_t process_id,
    std::size_t module_index) {
    UniqueHandle snapshot{::CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id)};
    if (!snapshot) {
        return std::nullopt;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Module32FirstW(snapshot.get(), &entry)) {
        return std::nullopt;
    }
    std::size_t current = 0;
    do {
        if (current++ == module_index) {
            return RemoteModule{
                reinterpret_cast<VirtualAddress>(entry.modBaseAddr),
                entry.modBaseSize,
                entry.szModule,
                entry.szExePath,
            };
        }
    } while (::Module32NextW(snapshot.get(), &entry));
    return std::nullopt;
}

}
