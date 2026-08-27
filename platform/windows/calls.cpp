#include "platform/windows/windows.hpp"

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
#include <type_traits>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>

namespace makima::platform::windows {

extern "C" NTSTATUS NTAPI NtSetInformationJobObject(
    HANDLE job,
    JOBOBJECTINFOCLASS information_class,
    void* information,
    ULONG information_size);

extern "C" NTSTATUS NTAPI NtSetInformationFile(
    HANDLE file,
    IO_STATUS_BLOCK* io_status,
    void* information,
    ULONG information_size,
    FILE_INFORMATION_CLASS information_class);

bool find_pattern_in_loaded_image_sections(
    void*,
    const char* image_path,
    const void* pattern,
    std::uint32_t pattern_size,
    std::uint32_t* section_rva,
    std::uint32_t* section_size,
    std::uint32_t* section_index,
    std::uintptr_t* image_base) noexcept {
    if (section_rva == nullptr || section_size == nullptr || section_index == nullptr ||
        image_base == nullptr) {
        return false;
    }
    *section_rva = 0;
    *section_size = 0;
    *section_index = 0;
    *image_base = 0;
    if (image_path == nullptr || pattern == nullptr || pattern_size == 0) return false;

    HMODULE module = LoadLibraryExA(image_path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (module == nullptr) return false;
    const auto release_module = std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)>(
        module, FreeLibrary);

    const auto* headers = static_cast<const IMAGE_NT_HEADERS*>(RtlImageNtHeader(module));
    if (headers == nullptr || headers->FileHeader.NumberOfSections == 0) return false;

    const auto* expected = static_cast<const std::byte*>(pattern);
    const IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(headers);
    for (std::uint32_t index = 0; index < headers->FileHeader.NumberOfSections; ++index) {
        const auto& section = sections[index];
        const std::uint32_t size = section.Misc.VirtualSize;
        if (size < pattern_size) continue;
        const auto* begin = reinterpret_cast<const std::byte*>(module) + section.VirtualAddress;
        const auto* found = static_cast<const std::byte*>(nullptr);
        for (std::uint32_t offset = 0; offset <= size - pattern_size; ++offset) {
            if (std::memcmp(begin + offset, expected, pattern_size) == 0) {
                found = begin + offset;
                break;
            }
        }
        if (found == nullptr) continue;

        *section_rva = section.VirtualAddress;
        *section_size = size;
        *section_index = index;
        *image_base = reinterpret_cast<std::uintptr_t>(module);
        return true;
    }
    return false;
}

bool call_nt_set_information_job_object(NativeJobInformationRequest* request) noexcept {
    if (request == nullptr || request->job == nullptr) return false;

    std::array<std::uint64_t, 2> information{request->value, 0};
    NTSTATUS status = NtSetInformationJobObject(
        request->job,
        static_cast<JOBOBJECTINFOCLASS>(0x28),
        information.data(),
        static_cast<ULONG>(sizeof(information)));
    if (status == static_cast<NTSTATUS>(0xC0000004L)) {
        status = NtSetInformationJobObject(
            request->job,
            static_cast<JOBOBJECTINFOCLASS>(0x28),
            information.data(),
            static_cast<ULONG>(sizeof(information.front())));
    }
    if (status < 0) return false;
    request->completed = 1;
    return true;
}

NTSTATUS call_nt_set_information_file(
    HANDLE file,
    FILE_INFORMATION_CLASS information_class,
    std::span<std::byte> information) noexcept {
    if (file == nullptr || information.empty()) {
        return static_cast<NTSTATUS>(0xC000000DL);
    }
    IO_STATUS_BLOCK io_status{};
    return NtSetInformationFile(
        file,
        &io_status,
        information.data(),
        static_cast<ULONG>(information.size()),
        information_class);
}

std::uint64_t format_system_error_message(
    wchar_t* destination,
    std::size_t capacity,
    SecurityFailureContext* context) noexcept {
    if (destination == nullptr || capacity == 0 || context == nullptr) return ERROR_INVALID_PARAMETER;
    destination[0] = L'\0';
    std::array<wchar_t, 0x100> system_message{};
    const DWORD message_id = (context->flags & 8U) == 0
        ? context->error_code
        : context->nt_status;
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        message_id,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        system_message.data(),
        static_cast<DWORD>(system_message.size()),
        nullptr);
    const char* failure_mode = "";
    switch (context->failure_class) {
    case 0: failure_mode = (context->flags & 8U) != 0 ? "ReturnNt" : "ReturnHr"; break;
    case 1: failure_mode = (context->flags & 8U) != 0 ? "LogNt" : "LogHr"; break;
    case 3: failure_mode = "FailFast"; break;
    default: break;
    }
    const int written = swprintf_s(
        destination,
        capacity,
        L"%hs!%hs tid(%x) %08X %ws Msg:[%ws] CallContext:[%hs]\n",
        context->module == nullptr ? "" : context->module,
        context->function == nullptr ? failure_mode : context->function,
        context->thread_id == 0 ? GetCurrentThreadId() : context->thread_id,
        message_id,
        system_message.data(),
        context->message == nullptr ? L"" : context->message,
        context->call_context == nullptr ? "" : context->call_context);
    return written < 0 ? ERROR_INSUFFICIENT_BUFFER : ERROR_SUCCESS;
}

HANDLE call_open_semaphore_w(std::wstring_view value, DWORD access) {
    std::wstring owned(value); return OpenSemaphoreW(access, FALSE, owned.c_str());
}

bool call_release_semaphore(HANDLE semaphore, LONG release_count, LONG* previous_count) {
    return ReleaseSemaphore(semaphore, release_count, previous_count) != FALSE;
}

HANDLE call_create_semaphore_ex_w(std::wstring_view value, LONG initial_count, LONG maximum_count) {
    std::wstring owned(value); return CreateSemaphoreExW(nullptr, initial_count, maximum_count, owned.c_str(), 0,
        SYNCHRONIZE | SEMAPHORE_MODIFY_STATE);
}

std::uint64_t call_wait_for_single_object_ex(WaitForSecurityEventRequest* request) noexcept {
    if (request == nullptr || request->object == nullptr) return 0;
    request->result = WaitForSingleObjectEx(
        request->object, request->timeout, request->alertable ? TRUE : FALSE);
    return request->result == WAIT_FAILED ? 0U : 1U;
}

}
