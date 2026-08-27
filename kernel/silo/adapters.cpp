#include "kernel/silo/silo.hpp"

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <utility>

#pragma comment(lib, "ntdll.lib")

#if defined(_MSC_VER)
extern "C" void __cdecl _Init_thread_abort(int*) noexcept;
#endif

extern "C" {

__declspec(dllimport) NTSTATUS NTAPI NtAssignProcessToJobObject(
    HANDLE job_handle,
    HANDLE process_handle);
__declspec(dllimport) NTSTATUS NTAPI NtClose(HANDLE handle);
__declspec(dllimport) NTSTATUS NTAPI NtCreateDirectoryObjectEx(
    PHANDLE directory_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    HANDLE shadow_directory_handle,
    ULONG flags);
__declspec(dllimport) NTSTATUS NTAPI NtCreateJobObject(
    PHANDLE job_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes);
__declspec(dllimport) NTSTATUS NTAPI NtCreateUserProcess(
    PHANDLE process_handle,
    PHANDLE thread_handle,
    ACCESS_MASK process_desired_access,
    ACCESS_MASK thread_desired_access,
    POBJECT_ATTRIBUTES process_object_attributes,
    POBJECT_ATTRIBUTES thread_object_attributes,
    ULONG process_flags,
    ULONG thread_flags,
    void* process_parameters,
    void* create_info,
    void* attribute_list);
__declspec(dllimport) NTSTATUS NTAPI NtDeviceIoControlFile(
    HANDLE file_handle,
    HANDLE event,
    PIO_APC_ROUTINE apc_routine,
    void* apc_context,
    PIO_STATUS_BLOCK io_status,
    ULONG control_code,
    void* input_buffer,
    ULONG input_size,
    void* output_buffer,
    ULONG output_size);
__declspec(dllimport) NTSTATUS NTAPI NtOpenDirectoryObject(
    PHANDLE directory_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes);
__declspec(dllimport) NTSTATUS NTAPI NtOpenEvent(
    PHANDLE event_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes);
__declspec(dllimport) NTSTATUS NTAPI NtOpenFile(
    PHANDLE file_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    PIO_STATUS_BLOCK io_status,
    ULONG share_access,
    ULONG open_options);
__declspec(dllimport) NTSTATUS NTAPI NtQueryInformationJobObject(
    HANDLE job_handle,
    JOBOBJECTINFOCLASS information_class,
    void* information,
    ULONG information_size,
    PULONG returned_size);
__declspec(dllimport) NTSTATUS NTAPI NtSetEvent(
    HANDLE event_handle,
    PLONG previous_state);
__declspec(dllimport) NTSTATUS NTAPI NtSetInformationFile(
    HANDLE file_handle,
    PIO_STATUS_BLOCK io_status,
    void* information,
    ULONG information_size,
    FILE_INFORMATION_CLASS information_class);
__declspec(dllimport) NTSTATUS NTAPI NtSetInformationJobObject(
    HANDLE job_handle,
    JOBOBJECTINFOCLASS information_class,
    void* information,
    ULONG information_size);

}

namespace makima::kernel::silo {
namespace {

constexpr NTSTATUS status_invalid_parameter = static_cast<NTSTATUS>(0xC000000DL);
constexpr ACCESS_MASK maximum_allowed_access = 0x02000000;
constexpr ACCESS_MASK job_object_all_access = 0x001F003F;
constexpr ULONG object_case_insensitive = 0x00000040;
constexpr ULONG file_completion_notification_class = 41;
constexpr ULONG skip_set_event_on_handle = 0x00000002;
constexpr ULONG skip_user_event_on_fast_io = 0x00000004;
constexpr ULONG job_create_silo_class = 35;
constexpr ULONG job_silo_root_directory_class = 37;
constexpr ULONG job_silo_ready_limit = 0x00400000;
constexpr ULONG silo_root_directory_flags = 0x00000007;
constexpr ULONG process_create_inherit_handles = 0x00000004;
constexpr std::uintptr_t process_job_list_attribute = 0x00020013;
constexpr std::size_t native_query_buffer_size = 0x1000;

int context_initialization_epoch{};
int handle_initialization_epoch{};
int process_initialization_epoch{};
int job_initialization_epoch{};
int namespace_initialization_epoch{};
int device_initialization_epoch{};
int record_initialization_epoch{};
int buffer_initialization_epoch{};
int query_initialization_epoch{};
int attribute_initialization_epoch{};
int process_parameters_initialization_epoch{};
int create_info_initialization_epoch{};
int query_cache_initialization_epoch{};
int security_cache_initialization_epoch{};
int job_information_initialization_epoch{};
int namespace_path_initialization_epoch{};
int ksec_request_initialization_epoch{};
int ksec_output_initialization_epoch{};
int lsa_registration_initialization_epoch{};
int silo_teardown_initialization_epoch{};

constexpr std::uint64_t avalanche_first_multiplier = 0xBF58476D1CE4E5B9ULL;
constexpr std::uint64_t avalanche_second_multiplier = 0x94D049BB133111EBULL;
constexpr std::uint64_t cookie_round_increment = 0x9E3779B97F4A7C15ULL;
constexpr std::uint64_t dispatch_salt_mask = 0xD6E8FEB86659FD93ULL;
constexpr std::uint64_t record_key_mask = 0xA0761D6478BD642FULL;
constexpr std::uint64_t record_value_mask = 0xE7037ED1A0B428DBULL;
constexpr std::uint64_t nonce_round_increment = 0x6170786593810FABULL;
constexpr std::uint64_t payload_hash_offset_basis = 0xCBF29CE484222325ULL;
constexpr std::uint64_t payload_hash_prime = 0x100000001B3ULL;



constexpr std::uintptr_t query_buffer_source_va = 0;
constexpr std::size_t query_buffer_size = 0x1000;
constexpr std::uintptr_t security_buffer_source_va = 1;
constexpr std::size_t security_buffer_size = 0x400;

struct FileCompletionNotification final {
    ULONG flags;
};

struct ExtendedJobLimitInformation final {
    JOBOBJECT_BASIC_LIMIT_INFORMATION basic_limits;
    IO_COUNTERS io_counters;
    std::size_t process_memory_limit;
    std::size_t job_memory_limit;
    std::size_t peak_process_memory_used;
    std::size_t peak_job_memory_used;
    std::size_t total_job_memory_limit;
};

struct SiloRootDirectoryInformation final {
    union {
        ULONG control_flags;
        UNICODE_STRING path;
    };
};

struct ProcessCreateInformation final {
    std::size_t size;
    ULONG state;
    union {
        struct {
            ULONG init_flags;
            ACCESS_MASK additional_file_access;
        } initial;
        struct {
            ULONG output_flags;
            HANDLE file_handle;
            HANDLE section_handle;
            std::uint64_t native_process_parameters;
            ULONG wow64_process_parameters;
            ULONG current_parameter_flags;
            std::uint64_t native_peb_address;
            ULONG wow64_peb_address;
            std::uint64_t manifest_address;
            ULONG manifest_size;
        } success;
    } details;
};

struct ProcessAttribute final {
    std::uintptr_t attribute;
    std::size_t size;
    union {
        std::uintptr_t value;
        void* value_pointer;
    } data;
    std::size_t* returned_size;
};

struct ProcessAttributeList final {
    std::size_t total_length;
    ProcessAttribute attributes[1];
};

[[nodiscard]] bool nt_success(NTSTATUS status) noexcept {
    return status >= 0;
}

[[nodiscard]] NativeStatus native_status(NTSTATUS status) noexcept {
    return {static_cast<std::int32_t>(status)};
}

[[nodiscard]] HANDLE windows_handle(NativeHandle handle) noexcept {
    return reinterpret_cast<HANDLE>(handle);
}

[[nodiscard]] NativeHandle native_handle(HANDLE handle) noexcept {
    return reinterpret_cast<NativeHandle>(handle);
}

[[nodiscard]] OBJECT_ATTRIBUTES object_attributes(
    UNICODE_STRING& name,
    HANDLE root_directory = nullptr) noexcept {
    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = sizeof(attributes);
    attributes.RootDirectory = root_directory;
    attributes.ObjectName = &name;
    attributes.Attributes = object_case_insensitive;
    return attributes;
}

[[nodiscard]] UNICODE_STRING unicode_string(std::wstring& text) noexcept {
    const auto byte_length = text.size() * sizeof(wchar_t);
    UNICODE_STRING result{};
    result.Length = static_cast<USHORT>(byte_length);
    result.MaximumLength = static_cast<USHORT>(byte_length + sizeof(wchar_t));
    result.Buffer = text.data();
    return result;
}

void abort_initialization(int& initialization_epoch) noexcept {
#if defined(_MSC_VER)
    _Init_thread_abort(&initialization_epoch);
#else
    initialization_epoch = 0;
#endif
}

SiloBuffer& cached_buffer(SiloContext& context, std::uintptr_t source_va, std::size_t size) {
    const auto existing = std::find_if(
        context.buffers.begin(),
        context.buffers.end(),
        [=](const SiloBuffer& buffer) { return buffer.source_va == source_va; });
    if (existing != context.buffers.end()) {
        return *existing;
    }
    context.buffers.push_back({source_va, std::vector<std::byte>(size)});
    return context.buffers.back();
}

std::uint64_t avalanche(std::uint64_t mixed_value) noexcept {
    mixed_value ^= mixed_value >> 30;
    mixed_value *= avalanche_first_multiplier;
    mixed_value ^= mixed_value >> 27;
    mixed_value *= avalanche_second_multiplier;
    return mixed_value ^ (mixed_value >> 31);
}

}

NativeApi::NativeApi() {
    open_object = [](std::wstring_view path, std::uint32_t desired_access) {
        std::wstring path_text{path};
        auto object_name = unicode_string(path_text);
        auto attributes = object_attributes(object_name);
        HANDLE event_handle = nullptr;
        const auto status = NtOpenEvent(
            &event_handle,
            static_cast<ACCESS_MASK>(desired_access),
            &attributes);
        return nt_success(status) ? native_handle(event_handle) : NativeHandle{};
    };

    signal_event = [](NativeHandle event_handle) {
        return native_status(NtSetEvent(windows_handle(event_handle), nullptr));
    };

    open_device = [](std::wstring_view path) {
        std::wstring path_text{path};
        auto object_name = unicode_string(path_text);
        auto attributes = object_attributes(object_name);
        IO_STATUS_BLOCK io_status{};
        HANDLE file_handle = nullptr;
        auto status = NtOpenFile(
            &file_handle,
            GENERIC_READ | GENERIC_WRITE,
            &attributes,
            &io_status,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            0);
        if (!nt_success(status)) {
            return NativeHandle{};
        }

        FileCompletionNotification notification{
            skip_set_event_on_handle | skip_user_event_on_fast_io};
        status = NtSetInformationFile(
            file_handle,
            &io_status,
            &notification,
            sizeof(notification),
            static_cast<FILE_INFORMATION_CLASS>(file_completion_notification_class));
        if (!nt_success(status)) {
            NtClose(file_handle);
            return NativeHandle{};
        }
        return native_handle(file_handle);
    };

    device_control = [](
                         NativeHandle device_handle,
                         std::uint32_t control_code,
                         std::span<const std::byte> input,
                         std::size_t output_size) {
        DeviceControlResult result;
        if (input.size() > std::numeric_limits<ULONG>::max() ||
            output_size > std::numeric_limits<ULONG>::max()) {
            result.status = native_status(status_invalid_parameter);
            return result;
        }

        result.output.resize(output_size);
        IO_STATUS_BLOCK io_status{};
        const auto status = NtDeviceIoControlFile(
            windows_handle(device_handle),
            nullptr,
            nullptr,
            nullptr,
            &io_status,
            control_code,
            input.empty() ? nullptr : const_cast<std::byte*>(input.data()),
            static_cast<ULONG>(input.size()),
            result.output.empty() ? nullptr : result.output.data(),
            static_cast<ULONG>(result.output.size()));
        result.status = native_status(status);
        if (nt_success(status)) {
            const auto completed = std::min<std::size_t>(
                result.output.size(), io_status.Information);
            result.output.resize(completed);
        } else {
            result.output.clear();
        }
        return result;
    };

    create_job = [] {
        HANDLE job_handle = nullptr;
        const auto status =
            NtCreateJobObject(&job_handle, job_object_all_access, nullptr);
        return nt_success(status) ? native_handle(job_handle) : NativeHandle{};
    };

    configure_silo_job = [](NativeHandle job_handle) {
        const auto native_job = windows_handle(job_handle);
        ExtendedJobLimitInformation limits{};
        limits.basic_limits.LimitFlags = job_silo_ready_limit;
        auto status = NtSetInformationJobObject(
            native_job,
            JobObjectExtendedLimitInformation,
            &limits,
            sizeof(limits));
        if (!nt_success(status)) {
            return native_status(status);
        }

        status = NtSetInformationJobObject(
            native_job,
            static_cast<JOBOBJECTINFOCLASS>(job_create_silo_class),
            nullptr,
            0);
        if (!nt_success(status)) {
            return native_status(status);
        }

        const auto current_process =
            reinterpret_cast<HANDLE>(static_cast<std::intptr_t>(-7));
        status = NtAssignProcessToJobObject(native_job, current_process);
        if (!nt_success(status)) {
            return native_status(status);
        }

        SiloRootDirectoryInformation root_directory{};
        root_directory.control_flags = silo_root_directory_flags;
        status = NtSetInformationJobObject(
            native_job,
            static_cast<JOBOBJECTINFOCLASS>(job_silo_root_directory_class),
            &root_directory,
            sizeof(root_directory));
        return native_status(status);
    };

    assign_process_to_job = [](NativeHandle job_handle, NativeHandle process_handle) {
        return native_status(NtAssignProcessToJobObject(
            windows_handle(job_handle), windows_handle(process_handle)));
    };

    create_process_in_job = [](NativeHandle job_handle) {
        if (job_handle == 0) {
            return NativeHandle{};
        }

        HANDLE job_list[]{windows_handle(job_handle)};
        ProcessCreateInformation create_information{};
        create_information.size = sizeof(create_information);

        ProcessAttributeList attributes{};
        attributes.total_length = sizeof(attributes);
        attributes.attributes[0].attribute = process_job_list_attribute;
        attributes.attributes[0].size = sizeof(job_list);
        attributes.attributes[0].data.value_pointer = job_list;

        HANDLE process_handle = nullptr;
        HANDLE thread_handle = nullptr;
        const auto status = NtCreateUserProcess(
            &process_handle,
            &thread_handle,
            maximum_allowed_access,
            maximum_allowed_access,
            nullptr,
            nullptr,
            process_create_inherit_handles,
            0,
            nullptr,
            &create_information,
            &attributes);
        if (!nt_success(status)) {
            return NativeHandle{};
        }
        if (thread_handle != nullptr) {
            NtClose(thread_handle);
        }
        return native_handle(process_handle);
    };

    query_job = [](NativeHandle job_handle, std::uint32_t information_class) {
        std::vector<std::byte> information(native_query_buffer_size);
        ULONG returned_size = 0;
        const auto status = NtQueryInformationJobObject(
            windows_handle(job_handle),
            static_cast<JOBOBJECTINFOCLASS>(information_class),
            information.data(),
            static_cast<ULONG>(information.size()),
            &returned_size);
        if (!nt_success(status)) {
            return std::vector<std::byte>{};
        }
        if (information_class == job_silo_root_directory_class &&
            information.size() >= sizeof(SiloRootDirectoryInformation)) {
            const auto& root_directory =
                *reinterpret_cast<const SiloRootDirectoryInformation*>(
                    information.data());
            if (root_directory.path.Buffer != nullptr &&
                root_directory.path.Length != 0) {
                const auto* path_bytes = reinterpret_cast<const std::byte*>(
                    root_directory.path.Buffer);
                return std::vector<std::byte>(
                    path_bytes, path_bytes + root_directory.path.Length);
            }
        }
        if (returned_size != 0) {
            information.resize(std::min<std::size_t>(information.size(), returned_size));
        }
        return information;
    };

    open_directory = [](std::wstring_view path) {
        std::wstring path_text{path};
        auto object_name = unicode_string(path_text);
        auto attributes = object_attributes(object_name);
        HANDLE directory_handle = nullptr;
        const auto status = NtOpenDirectoryObject(
            &directory_handle, maximum_allowed_access, &attributes);
        return nt_success(status) ? native_handle(directory_handle) : NativeHandle{};
    };

    create_directory = [](NativeHandle root_handle, std::wstring_view name) {
        std::wstring directory_name{name};
        auto object_name = unicode_string(directory_name);
        auto attributes = object_attributes(
            object_name, windows_handle(root_handle));
        HANDLE directory_handle = nullptr;
        const auto status = NtCreateDirectoryObjectEx(
            &directory_handle,
            maximum_allowed_access,
            &attributes,
            nullptr,
            0);
        return nt_success(status) ? native_handle(directory_handle) : NativeHandle{};
    };

    close = [](NativeHandle handle) {
        if (handle != 0) {
            NtClose(windows_handle(handle));
        }
    };
}

NativeApi make_native_api() {
    return NativeApi{};
}


void abort_context_initialization() noexcept {
    abort_initialization(context_initialization_epoch);
}


void abort_handle_initialization() noexcept {
    abort_initialization(handle_initialization_epoch);
}


void abort_process_initialization() noexcept {
    abort_initialization(process_initialization_epoch);
}


void abort_job_initialization() noexcept {
    abort_initialization(job_initialization_epoch);
}


void abort_namespace_initialization() noexcept {
    abort_initialization(namespace_initialization_epoch);
}


void abort_device_initialization() noexcept {
    abort_initialization(device_initialization_epoch);
}


void abort_record_initialization() noexcept {
    abort_initialization(record_initialization_epoch);
}


void abort_buffer_initialization() noexcept {
    abort_initialization(buffer_initialization_epoch);
}


void abort_query_initialization() noexcept {
    abort_initialization(query_initialization_epoch);
}


void abort_attribute_initialization() noexcept {
    abort_initialization(attribute_initialization_epoch);
}


void abort_process_parameters_initialization() noexcept {
    abort_initialization(process_parameters_initialization_epoch);
}


void abort_create_info_initialization() noexcept {
    abort_initialization(create_info_initialization_epoch);
}


void abort_query_cache_initialization() noexcept {
    abort_initialization(query_cache_initialization_epoch);
}


void abort_security_cache_initialization() noexcept {
    abort_initialization(security_cache_initialization_epoch);
}


void abort_job_information_initialization() noexcept {
    abort_initialization(job_information_initialization_epoch);
}


void abort_namespace_path_initialization() noexcept {
    abort_initialization(namespace_path_initialization_epoch);
}


void abort_ksec_request_initialization() noexcept {
    abort_initialization(ksec_request_initialization_epoch);
}


void abort_ksec_output_initialization() noexcept {
    abort_initialization(ksec_output_initialization_epoch);
}


void abort_lsa_registration_initialization() noexcept {
    abort_initialization(lsa_registration_initialization_epoch);
}


void abort_silo_teardown_initialization() noexcept {
    abort_initialization(silo_teardown_initialization_epoch);
}



std::uint64_t mix_silo_cookie(std::uint64_t cookie, std::uint64_t salt) noexcept {
    auto mixed_cookie = cookie ^ std::rotl(salt, 13);
    mixed_cookie += cookie_round_increment;
    return avalanche(mixed_cookie);
}



std::uint64_t derive_silo_dispatch_key(
    std::uint64_t dispatch_state,
    std::uint64_t salt) noexcept {
    auto dispatch_key =
        dispatch_state + std::rotl(salt ^ dispatch_salt_mask, 21);
    dispatch_key ^= std::rotr(dispatch_state, 11);
    return avalanche(dispatch_key);
}





wchar_t* decode_protected_utf16_140774380(
    const std::uint16_t* source) {
    auto* output = static_cast<wchar_t*>(::operator new(13U * sizeof(wchar_t)));
    const auto rotate = [](std::uint16_t value, int shift) {
        return std::rotl(value, shift);
    };
    output[0] = static_cast<wchar_t>(rotate(source[0], 13) ^ 0x4096U);
    output[1] = static_cast<wchar_t>(rotate(source[1], 13) ^ 0x6031U);
    output[2] = static_cast<wchar_t>(rotate(source[2], 13) ^ 0x00F8U);
    output[3] = static_cast<wchar_t>(rotate(source[3], 13) ^ 0xA098U);
    output[4] = static_cast<wchar_t>(rotate(source[4], 13) ^ 0xC04AU);
    output[5] = static_cast<wchar_t>(rotate(source[5], 13) ^ 0xE011U);
    output[6] = static_cast<wchar_t>(rotate(source[6], 13) ^ 0xA08AU);
    output[7] = static_cast<wchar_t>(rotate(source[7], 12) ^ 0xE044U);
    output[8] = static_cast<wchar_t>(rotate(source[8], 14) ^ 0xC03BU);
    output[9] = static_cast<wchar_t>(rotate(source[9], 14) ^ 0x8042U);
    output[10] = static_cast<wchar_t>(rotate(source[10], 11) ^ 0xF83CU);
    output[11] = static_cast<wchar_t>(rotate(source[11], 14) ^ 0x0037U);
    output[12] = L'\0';
    return output;
}


std::byte* decode_protected_bytes_140776a60(
    const std::byte* source) {
    auto* output = static_cast<std::byte*>(::operator new(22));
    const auto input = [source](std::size_t index) {
        return std::to_integer<std::uint8_t>(source[index]);
    };
    const auto result = [](std::uint8_t value) {
        return static_cast<std::byte>(value);
    };
    output[0] = result(std::rotl(input(0), 6) ^ 0xBFU);
    output[1] = result(std::rotl(input(1), 6) ^ 0x62U);
    output[2] = result(std::rotl(input(2), 7) ^ 0x08U);
    output[3] = result(std::rotl(input(3), 6) ^ 0x73U);
    output[4] = result(std::rotl(input(4), 7) ^ 0xFDU);
    output[5] = result(std::rotl(input(5), 5) ^ 0x19U);
    output[6] = result(std::rotl(input(6), 7) ^ 0xCBU);
    output[7] = result(std::rotl(input(7), 5) ^ 0x2FU);
    output[8] = result(input(8) ^ 0xBAU);
    output[9] = result(std::rotl(input(9), 5) ^ 0xCBU);
    output[10] = result(input(10) ^ 0xBAU);
    output[11] = result(std::rotl(input(11), 5) ^ 0x68U);
    output[12] = result(input(12) ^ 0xBAU);
    output[13] = result(input(13) ^ 0xBAU);
    output[14] = result(input(14) ^ 0xBAU);
    output[15] = result(input(15) ^ 0xBAU);
    output[16] = result(std::rotl(input(16), 1) ^ 0x4FU);
    output[17] = result(input(17) ^ 0xBAU);
    output[18] = result(std::rotl(input(18), 1) ^ 0x0BU);
    output[19] = result(std::rotl(input(19), 1) ^ 0x79U);
    output[20] = result(std::rotl(input(20), 1) ^ 0x80U);
    output[21] = std::byte{};
    return output;
}


std::uint64_t fold_silo_record_key(
    std::uint64_t record_key,
    std::uint64_t record_value) noexcept {
    auto fingerprint =
        (record_key ^ record_key_mask) * (record_value ^ record_value_mask);
    fingerprint ^= std::rotl(record_key, 27) ^ std::rotr(record_value, 19);
    return avalanche(fingerprint);
}


std::uint64_t scramble_silo_nonce(std::uint64_t nonce, std::uint64_t sequence) noexcept {
    nonce += nonce_round_increment;
    nonce ^= std::rotl(sequence, 32);
    nonce = std::rotl(nonce, 16) + sequence;
    nonce ^= std::rotr(sequence, 20);
    return avalanche(nonce);
}


std::byte* decode_protected_bytes_140784ba0(
    const std::byte* source) {
    auto* output = static_cast<std::byte*>(::operator new(41));
    const auto input = [source](std::size_t index) {
        return std::to_integer<std::uint8_t>(source[index]);
    };
    const auto result = [](std::uint8_t value) {
        return static_cast<std::byte>(value);
    };
    output[0] = result(input(0) ^ 0x97U); output[1] = result(input(1) ^ 0xC4U);
    output[2] = result(input(2) ^ 0x71U); output[3] = result(input(3) ^ 0x7AU);
    output[4] = result(input(4) ^ 0xB1U); output[5] = result(std::rotl(input(5), 7) ^ 0x94U);
    output[6] = result(std::rotl(input(6), 1) ^ 0x39U); output[7] = result(std::rotl(input(7), 1) ^ 0xB3U);
    output[8] = result(std::rotl(input(8), 7) ^ 0xB4U); output[9] = result(std::rotl(input(9), 1) ^ 0xD6U);
    output[10] = result(std::rotl(input(10), 7) ^ 0x14U); output[11] = result(std::rotl(input(11), 1) ^ 0x0AU);
    output[12] = result(std::rotl(input(12), 2) ^ 0x91U); output[13] = result(std::rotl(input(13), 2) ^ 0x7EU);
    output[14] = result(std::rotl(input(14), 2) ^ 0x31U); output[15] = result(std::rotl(input(15), 2) ^ 0x79U);
    output[16] = result(std::rotl(input(16), 2) ^ 0xABU); output[17] = result(std::rotl(input(17), 2) ^ 0x83U);
    output[18] = result(std::rotl(input(18), 2) ^ 0x04U); output[19] = result(std::rotl(input(19), 1) ^ 0xD0U);
    output[20] = result(std::rotl(input(20), 2) ^ 0xBEU); output[21] = result(std::rotl(input(21), 1) ^ 0x7AU);
    output[22] = result(std::rotl(input(22), 3) ^ 0x42U); output[23] = result(std::rotl(input(23), 3) ^ 0x08U);
    output[24] = result(std::rotl(input(24), 1) ^ 0x5DU); output[25] = result(std::rotl(input(25), 1) ^ 0x19U);
    output[26] = result(std::rotl(input(26), 1) ^ 0xFFU); output[27] = result(std::rotl(input(27), 3) ^ 0x76U);
    output[28] = result(std::rotl(input(28), 4) ^ 0x18U); output[29] = result(std::rotl(input(29), 4) ^ 0x71U);
    output[30] = result(std::rotl(input(30), 4)); output[31] = result(std::rotl(input(31), 4) ^ 0x68U);
    output[32] = result(std::rotl(input(32), 4) ^ 0xEBU); output[33] = result(std::rotl(input(33), 4) ^ 0x6BU);
    output[34] = result(std::rotl(input(34), 4) ^ 0x45U); output[35] = result(std::rotl(input(35), 3) ^ 0xE1U);
    output[36] = result(std::rotl(input(36), 4) ^ 0x93U); output[37] = result(std::rotl(input(37), 4) ^ 0x4EU);
    output[38] = result(std::rotl(input(38), 3) ^ 0x43U); output[39] = result(std::rotl(input(39), 3) ^ 0xA5U);
    output[40] = std::byte{};
    return output;
}


std::uint64_t derive_ksec_request_tag(
    std::uint64_t kernel_function,
    std::uint64_t argument) noexcept {
    const auto request_key = fold_silo_record_key(kernel_function, argument);
    return mix_silo_cookie(
        request_key, kernel_function ^ std::rotl(argument, 7));
}


SiloBuffer& cached_query_buffer(SiloContext& context) {
    return cached_buffer(context, query_buffer_source_va, query_buffer_size);
}


SiloBuffer& cached_security_buffer(SiloContext& context) {
    return cached_buffer(context, security_buffer_source_va, security_buffer_size);
}



wchar_t* cached_se_debug_privilege_name() {
    static wchar_t* const value = allocate_silo_se_debug_privilege(
        reinterpret_cast<const std::uint16_t*>(0x1414DAADAULL));
    return value;
}

wchar_t* cached_se_impersonate_privilege_name() {
    static wchar_t* const value = allocate_silo_se_impersonate_privilege(
        reinterpret_cast<const std::uint16_t*>(0x1414DAAFEULL));
    return value;
}



std::uint64_t hash_silo_payload(
    std::span<const std::byte> payload,
    std::uint64_t seed) noexcept {
    auto hash = seed ^ payload_hash_offset_basis;
    for (const auto element : payload) {
        hash ^= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(element));
        hash *= payload_hash_prime;
        hash = std::rotl(hash, 5);
    }
    return avalanche(hash ^ static_cast<std::uint64_t>(payload.size()));
}

}
