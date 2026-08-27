#include "platform/windows/windows.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
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
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>

namespace makima::platform::windows {

FARPROC resolve_named_export_from_module(HMODULE module, std::string_view export_name) {
    if (module == nullptr || export_name.empty()) return nullptr; std::string owned(export_name); return GetProcAddress(module, owned.c_str());
}

std::wstring get_wide_module_file_path_for_update_event(HMODULE module) {
    std::wstring path(260U, L'\0'); DWORD size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size()));
    while (size == path.size() && path.size() < 32768U) { path.resize(path.size() * 2U); size = GetModuleFileNameW(module, path.data(), static_cast<DWORD>(path.size())); }
    if (size == 0U) return {};
    path.resize(size);
    const std::filesystem::path parsed{path};
    const std::wstring parent = parsed.parent_path().native();
    const std::wstring filename = parsed.filename().native();
    std::vector<wchar_t> rebuilt(parent.size() + filename.size() + 2U, L'\0');
    if (wcscpy_s(rebuilt.data(), rebuilt.size(), parent.c_str()) != 0 ||
        wcscat_s(rebuilt.data(), rebuilt.size(), L"\\") != 0 ||
        wcscat_s(rebuilt.data(), rebuilt.size(), filename.c_str()) != 0) {
        return {};
    }
    return std::wstring{rebuilt.data()};
}

char* copy_ansi_module_file_path(
    char* destination,
    int* copied_length,
    HMODULE* module,
    std::size_t capacity) noexcept {
    if (copied_length != nullptr) *copied_length = 0;
    if (destination == nullptr || capacity == 0 || capacity > MAXDWORD) return nullptr;
    destination[0] = '\0';
    const HMODULE selected_module = module == nullptr ? nullptr : *module;
    const DWORD copied = GetModuleFileNameA(
        selected_module, destination, static_cast<DWORD>(capacity));
    if (copied == 0 || copied >= capacity) {
        destination[capacity - 1] = '\0';
        return nullptr;
    }
    const std::size_t measured = std::strlen(destination);
    if (measured != copied) return nullptr;
    if (copied_length != nullptr) *copied_length = static_cast<int>(measured);
    return destination;
}

const char* get_current_ansi_module_file_path() noexcept {
    static std::array<char, 0x104> module_path{};
    static int module_path_length = 0;
    static const bool initialized = []() noexcept {
        const DWORD copied = GetModuleFileNameA(
            nullptr, module_path.data(), static_cast<DWORD>(module_path.size()));
        if (copied == 0 || copied >= module_path.size()) return false;
        module_path_length = static_cast<int>(std::strlen(module_path.data()));
        return module_path_length == static_cast<int>(copied);
    }();
    return initialized && module_path_length != 0 ? module_path.data() : "";
}

}
