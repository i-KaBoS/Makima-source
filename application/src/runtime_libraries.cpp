#include "makima/application/runtime_libraries.hpp"

#include "makima/application/common.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace makima::application {
namespace {

constexpr std::array<std::string_view, 16> required_runtime_modules{
    "user32.dll",
    "dwmapi.dll",
    "winhttp.dll",
    "bcrypt.dll",
    "ole32.dll",
    "d2d1.dll",
    "dwrite.dll",
    "d3d12.dll",
    "d3d11.dll",
    "dxgi.dll",
    "advapi32.dll",
    "shlwapi.dll",
    "crypt32.dll",
    "setupapi.dll",
    "hid.dll",
    "powrprof.dll",
};

template <class Function>
Function resolve(HMODULE module, const char* name) {
    if (module == nullptr)
        throw ApplicationError("cannot resolve an API from an unloaded runtime module");
    const auto function = reinterpret_cast<Function>(GetProcAddress(module, name));
    if (function == nullptr)
        throw ApplicationError("required runtime API is unavailable: " + std::string{name});
    return function;
}

std::wstring system_library_path(std::string_view name) {
    std::array<wchar_t, MAX_PATH> system_directory{};
    const UINT length = GetSystemDirectoryW(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (length == 0 || length >= system_directory.size()) {
        constexpr wchar_t fallback_system_directory[] = L"C:\\Windows\\System32";
        wcscpy_s(
            system_directory.data(), system_directory.size(), fallback_system_directory);
    }

    constexpr wchar_t library_path_format[] = L"%s\\%s";
    std::array<wchar_t, MAX_PATH * 2> path{};
    const std::wstring name_copy{name.begin(), name.end()};
    int written = 0;
    if (name == "winhttp.dll") {
        constexpr wchar_t winhttp_path_format[] = L"%s\\winhttp.dll";
        written = _snwprintf_s(
            path.data(), path.size(), _TRUNCATE,
            winhttp_path_format, system_directory.data());
    } else {
        written = _snwprintf_s(
            path.data(), path.size(), _TRUNCATE, library_path_format,
            system_directory.data(), name_copy.c_str());
    }
    if (written < 0) {
        throw ApplicationError("Windows system-library path is too long");
    }
    return path.data();
}

struct ExecutableSection {
    std::size_t virtual_address{};
    std::size_t virtual_size{};
};

class FileHandle final {
public:
    explicit FileHandle(HANDLE value) noexcept : value_(value) {}
    ~FileHandle() {
        if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    }
    FileHandle(const FileHandle&) = delete;
    FileHandle& operator=(const FileHandle&) = delete;

    HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE value_{INVALID_HANDLE_VALUE};
};

std::optional<ExecutableSection> first_executable_section(
    const std::byte* image, std::size_t available_bytes) noexcept {
    if (image == nullptr || available_bytes < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew < 0)
        return std::nullopt;

    const auto nt_offset = static_cast<std::size_t>(dos_header->e_lfanew);
    if (nt_offset > available_bytes ||
        available_bytes - nt_offset < sizeof(IMAGE_NT_HEADERS64)) {
        return std::nullopt;
    }

    const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + nt_offset);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE ||
        nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::nullopt;
    }

    const auto section_offset = nt_offset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        nt_headers->FileHeader.SizeOfOptionalHeader;
    const auto section_count = static_cast<std::size_t>(nt_headers->FileHeader.NumberOfSections);
    if (section_offset > available_bytes ||
        section_count > (available_bytes - section_offset) / sizeof(IMAGE_SECTION_HEADER)) {
        return std::nullopt;
    }

    const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(image + section_offset);
    for (std::size_t index = 0; index < section_count; ++index) {
        const auto& section = sections[index];
        if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
            section.Misc.VirtualSize != 0) {
            return ExecutableSection{
                static_cast<std::size_t>(section.VirtualAddress),
                static_cast<std::size_t>(section.Misc.VirtualSize),
            };
        }
    }
    return std::nullopt;
}

}

RuntimeLibraries::~RuntimeLibraries() {
    for (auto iterator = entries_.rbegin(); iterator != entries_.rend(); ++iterator) {
        if (iterator->module != nullptr) FreeLibrary(iterator->module);
    }
}

RuntimeLibraries::RuntimeLibraries(RuntimeLibraries&& other) noexcept
    : entries_(std::exchange(other.entries_, {})) {}

RuntimeLibraries& RuntimeLibraries::operator=(RuntimeLibraries&& other) noexcept {
    if (this != &other) {
        for (auto iterator = entries_.rbegin(); iterator != entries_.rend(); ++iterator) {
            if (iterator->module != nullptr) FreeLibrary(iterator->module);
        }
        entries_ = std::exchange(other.entries_, {});
    }
    return *this;
}

HMODULE RuntimeLibraries::find(std::string_view module_name) const noexcept {
    for (const auto& entry : entries_)
        if (entry.name == module_name) return entry.module;
    return nullptr;
}



bool verify_loaded_winhttp_image() noexcept {
    try {
    const HMODULE loaded_module = GetModuleHandleW(L"winhttp.dll");
    if (loaded_module == nullptr) return false;

    const auto* loaded_bytes = reinterpret_cast<const std::byte*>(loaded_module);
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(loaded_bytes);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew < 0) return false;
    const auto* nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        loaded_bytes + static_cast<std::size_t>(dos_header->e_lfanew));
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE ||
        nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }
    const std::size_t loaded_image_size = nt_headers->OptionalHeader.SizeOfImage;
    const auto loaded_section = first_executable_section(loaded_bytes, loaded_image_size);
    if (!loaded_section) return false;

    const std::wstring path = system_library_path("winhttp.dll");
    FileHandle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (!file) return false;

    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file.get(), &file_size) || file_size.QuadPart <= 0 ||
        static_cast<unsigned long long>(file_size.QuadPart) >
            static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
        return false;
    }

    std::vector<std::byte> installed_image;
    installed_image.resize(static_cast<std::size_t>(file_size.QuadPart));

    std::size_t read_offset = 0;
    while (read_offset < installed_image.size()) {
        const auto remaining = installed_image.size() - read_offset;
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            remaining, std::numeric_limits<DWORD>::max()));
        DWORD bytes_read = 0;
        if (!ReadFile(file.get(), installed_image.data() + read_offset,
                requested, &bytes_read, nullptr) ||
            bytes_read == 0) {
            return false;
        }
        read_offset += bytes_read;
    }

    const auto installed_section = first_executable_section(
        installed_image.data(), installed_image.size());
    if (!installed_section) return false;

    const std::size_t bytes_to_compare = std::min(
        loaded_section->virtual_size, installed_section->virtual_size);
    if (bytes_to_compare == 0 ||
        loaded_section->virtual_address > loaded_image_size ||
        bytes_to_compare > loaded_image_size - loaded_section->virtual_address ||
        installed_section->virtual_address > installed_image.size() ||
        bytes_to_compare > installed_image.size() - installed_section->virtual_address) {
        return false;
    }

    return std::memcmp(
        loaded_bytes + loaded_section->virtual_address,
        installed_image.data() + installed_section->virtual_address,
        bytes_to_compare) == 0;
    } catch (...) {
        return false;
    }
}



RuntimeLibraries load_runtime_libraries() {
    RuntimeLibraries libraries;
    libraries.entries_.reserve(required_runtime_modules.size());
    for (const auto name : required_runtime_modules) {
        const std::wstring path = system_library_path(name);
        HMODULE module = LoadLibraryExW(
            path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == nullptr)
            throw ApplicationError("required runtime module is unavailable: " + std::string{name});
        libraries.entries_.push_back({name, module});
    }
    if (!verify_loaded_winhttp_image())
        throw ApplicationError("the loaded WinHTTP image failed its integrity check");
    return libraries;
}

RuntimeEntryPoints resolve_runtime_entry_points(const RuntimeLibraries& libraries) {
    RuntimeEntryPoints api;
    const HMODULE kernel32 = libraries.find("kernel32.dll") != nullptr
        ? libraries.find("kernel32.dll")
        : GetModuleHandleW(L"kernel32.dll");
    api.create_process = resolve<decltype(api.create_process)>(kernel32, "CreateProcessW");
    api.delete_file = resolve<decltype(api.delete_file)>(kernel32, "DeleteFileW");
    api.move_file = resolve<decltype(api.move_file)>(kernel32, "MoveFileW");
    api.get_system_directory = resolve<decltype(api.get_system_directory)>(
        kernel32, "GetSystemDirectoryW");
    api.get_firmware_environment_variable = resolve<decltype(api.get_firmware_environment_variable)>(
        kernel32, "GetFirmwareEnvironmentVariableA");
    api.thread_first = resolve<decltype(api.thread_first)>(kernel32, "Thread32First");
    api.thread_next = resolve<decltype(api.thread_next)>(kernel32, "Thread32Next");

    const HMODULE power = libraries.find("powrprof.dll");
    api.power_get_active_scheme = resolve<decltype(api.power_get_active_scheme)>(
        power, "PowerGetActiveScheme");
    const HMODULE crypt = libraries.find("crypt32.dll");
    api.crypt_decode_object = resolve<decltype(api.crypt_decode_object)>(
        crypt, "CryptDecodeObjectEx");

    const HMODULE winhttp = libraries.find("winhttp.dll");
    api.winhttp_open = resolve<decltype(api.winhttp_open)>(winhttp, "WinHttpOpen");
    api.winhttp_connect = resolve<decltype(api.winhttp_connect)>(winhttp, "WinHttpConnect");
    api.winhttp_open_request = resolve<decltype(api.winhttp_open_request)>(
        winhttp, "WinHttpOpenRequest");
    api.winhttp_send_request = resolve<decltype(api.winhttp_send_request)>(
        winhttp, "WinHttpSendRequest");
    api.winhttp_receive_response = resolve<decltype(api.winhttp_receive_response)>(
        winhttp, "WinHttpReceiveResponse");
    api.winhttp_close_handle = resolve<decltype(api.winhttp_close_handle)>(
        winhttp, "WinHttpCloseHandle");
    api.winhttp_set_option = resolve<decltype(api.winhttp_set_option)>(winhttp, "WinHttpSetOption");
    api.winhttp_add_headers = resolve<decltype(api.winhttp_add_headers)>(
        winhttp, "WinHttpAddRequestHeaders");
    api.winhttp_query_headers = resolve<decltype(api.winhttp_query_headers)>(
        winhttp, "WinHttpQueryHeaders");
    api.winhttp_query_option = resolve<decltype(api.winhttp_query_option)>(
        winhttp, "WinHttpQueryOption");
    api.winhttp_set_timeouts = resolve<decltype(api.winhttp_set_timeouts)>(
        winhttp, "WinHttpSetTimeouts");
    api.websocket_close = resolve<decltype(api.websocket_close)>(winhttp, "WinHttpWebSocketClose");
    api.websocket_complete_upgrade = resolve<decltype(api.websocket_complete_upgrade)>(
        winhttp, "WinHttpWebSocketCompleteUpgrade");
    api.websocket_receive = resolve<decltype(api.websocket_receive)>(
        winhttp, "WinHttpWebSocketReceive");
    api.websocket_send = resolve<decltype(api.websocket_send)>(winhttp, "WinHttpWebSocketSend");

    const HMODULE bcrypt = libraries.find("bcrypt.dll");
    api.bcrypt_random = resolve<decltype(api.bcrypt_random)>(bcrypt, "BCryptGenRandom");
    api.bcrypt_open_algorithm = resolve<decltype(api.bcrypt_open_algorithm)>(
        bcrypt, "BCryptOpenAlgorithmProvider");
    api.bcrypt_set_property = resolve<decltype(api.bcrypt_set_property)>(
        bcrypt, "BCryptSetProperty");
    api.bcrypt_generate_key = resolve<decltype(api.bcrypt_generate_key)>(
        bcrypt, "BCryptGenerateSymmetricKey");
    api.bcrypt_encrypt = resolve<decltype(api.bcrypt_encrypt)>(bcrypt, "BCryptEncrypt");
    return api;
}

const RuntimeEntryPoints& runtime_entry_points() {
    struct BoundRuntime final {
        RuntimeLibraries libraries{load_runtime_libraries()};
        RuntimeEntryPoints api{resolve_runtime_entry_points(libraries)};
    };
    static const BoundRuntime runtime;
    return runtime.api;
}

}
