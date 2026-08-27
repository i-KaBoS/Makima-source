#include "security/environment/environment.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cstdio>
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

namespace makima::security::environment {

static bool append_json_escape(std::string& output, std::string_view input) {
    static const char* const escaped_quote = allocate_json_quote_escape(
        reinterpret_cast<const std::uint8_t*>(0x1414DD27Dull));
    static const char* const escaped_backslash = allocate_json_backslash_escape(
        reinterpret_cast<const std::uint8_t*>(0x1414DD281ull));
    static const char* const escaped_newline = allocate_json_newline_escape(
        reinterpret_cast<const std::uint8_t*>(0x1414DD285ull));
    static const char* const escaped_carriage_return =
        allocate_json_carriage_return_escape(
            reinterpret_cast<const std::uint8_t*>(0x1414DD289ull));
    static const char* const escaped_tab = allocate_json_tab_escape(
        reinterpret_cast<const std::uint8_t*>(0x1414DD28Dull));
    static const char* const unicode_escape_format =
        allocate_json_unicode_escape_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DD291ull));
    for (const unsigned char value : input) {
        switch (value) {
        case '"': output += escaped_quote; break;
        case '\\': output += escaped_backslash; break;
        case '\n': output += escaped_newline; break;
        case '\r': output += escaped_carriage_return; break;
        case '\t': output += escaped_tab; break;
        default:
            if (value < 0x20U) {
                char escape[8]{};
                std::snprintf(
                    escape,
                    sizeof(escape),
                    unicode_escape_format,
                    static_cast<unsigned int>(value));
                output += escape;
            } else {
                output.push_back(static_cast<char>(value));
            }
        }
    }
    return true;
}



bool read_first_cache_record(
    const wchar_t* directory,
    void* output,
    std::uint32_t output_capacity,
    std::uint32_t* bytes_read) noexcept {
    if (bytes_read != nullptr) *bytes_read = 0;
    if (directory == nullptr || *directory == L'\0' || output == nullptr ||
        output_capacity == 0 || bytes_read == nullptr) {
        return false;
    }

    static const wchar_t* const search_format = allocate_cache_record_search_pattern(
        reinterpret_cast<const std::uint16_t*>(0x1414DD138ull));
    wchar_t search_pattern[MAX_PATH]{};
    if (_snwprintf_s(
            search_pattern,
            std::size(search_pattern),
            _TRUNCATE,
            search_format,
            directory) < 0) {
        return false;
    }

    WIN32_FIND_DATAW entry{};
    HANDLE search = FindFirstFileW(search_pattern, &entry);
    if (search == INVALID_HANDLE_VALUE) return false;
    const auto close_search = std::unique_ptr<void, decltype(&FindClose)>(search, FindClose);

    do {
        if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) continue;
        static const wchar_t* const path_format = allocate_cache_record_child_path_format(
            reinterpret_cast<const std::uint16_t*>(0x1414DD14Cull));
        wchar_t path[MAX_PATH]{};
        if (_snwprintf_s(
                path,
                std::size(path),
                _TRUNCATE,
                path_format,
                directory,
                entry.cFileName) < 0) {
            continue;
        }

        HANDLE file = CreateFileW(
            path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) continue;
        const auto close_file = std::unique_ptr<void, decltype(&CloseHandle)>(file, CloseHandle);
        DWORD received = 0;
        if (ReadFile(file, output, output_capacity, &received, nullptr) && received != 0) {
            *bytes_read = received;
            return true;
        }
    } while (FindNextFileW(search, &entry));
    return false;
}

bool validate_cache_record(std::span<const std::byte> record) noexcept {
    if (record.size() < 16 || record.size() > 0x0c800000U) return false;
    bool all_zero = true;
    for (const std::byte value : record.first(std::min<std::size_t>(record.size(), 64U))) {
        all_zero = all_zero && value == std::byte{};
    }
    return !all_zero;
}



void append_json_escaped_text(std::string* output, const char* input) {
    const std::size_t input_length = input == nullptr ? 0U : std::strlen(input);
    output->push_back('"');
    append_json_escape(
        *output,
        input == nullptr ? std::string_view{} : std::string_view{input, input_length});
    output->push_back('"');
}

}
