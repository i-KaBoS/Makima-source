#include "security/environment/environment.hpp"
#include "makima/application/identity.hpp"
#include "makima/application/sync_client.hpp"
#include "storage/registry/registry.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <cstring>
#include <memory>
#include <new>
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
#include "../../platform/include/makima/platform/security_monitor.hpp"
#include "../../process/pe_mapping/pe_mapping.hpp"
#include "embedded_guard_image.hpp"

extern "C" void __cdecl _Cnd_do_broadcast_at_thread_exit();
extern "C" [[noreturn]] void __cdecl _invoke_watson(
    const wchar_t* expression,
    const wchar_t* function_name,
    const wchar_t* file_name,
    unsigned int line_number,
    std::uintptr_t reserved);

namespace makima::telemetry::reporting {

namespace {

struct GuardCaptureState final {
    std::uint8_t initialized{};
    std::array<std::uint8_t, 7> reserved{};
    std::uintptr_t mapped_guard_image{};
};

struct GuardHostImageRange final {
    const void* image_base{};
    std::size_t image_size{};
};

using GuardInitFunction = bool(WINAPI*)(const GuardHostImageRange*);
using GuardShutdownFunction = void(WINAPI*)();
using GuardVerifyIntegrityFunction = bool(WINAPI*)();

GuardVerifyIntegrityFunction guard_verify_integrity{};
std::size_t guarded_text_size{};
std::uint32_t guarded_text_baseline_crc{};

static_assert(offsetof(GuardCaptureState, initialized) == 0);
static_assert(offsetof(GuardCaptureState, mapped_guard_image) == 8);
static_assert(detail::embedded_guard_image.size() == 0x2200);

[[nodiscard]] std::uint32_t crc32(
    const std::byte* bytes,
    std::size_t size) noexcept {
    std::uint32_t crc = 0xffffffffU;
    for (std::size_t index = 0; index < size; ++index) {
        crc ^= static_cast<std::uint8_t>(bytes[index]);
        for (unsigned int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

bool get_host_image_range(GuardHostImageRange* range) noexcept {
    if (range == nullptr) return false;
    const HMODULE module = GetModuleHandleW(nullptr);
    if (module == nullptr) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const std::byte*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage == 0) {
        return false;
    }
    const auto* text_base =
        reinterpret_cast<const std::byte*>(module) +
        nt->OptionalHeader.BaseOfCode;
    range->image_base = text_base;
    range->image_size = nt->OptionalHeader.SizeOfCode;
    guarded_text_size = range->image_size;
    guarded_text_baseline_crc = crc32(
        text_base,
        guarded_text_size);
    return true;
}

void report_guard_failure(const char* event_name, const char* detail) noexcept {
    async_capture_and_report_wrapper(event_name, 2, detail);
}

void report_guard_mapping_failure() noexcept {
    static const char* const detail =
        ::makima::storage::registry::
            allocate_check_manual_map_of_guard_dll_returned_invalid_mapping(
                0x1414DCA44ll);
    static const char* const event =
        ::makima::storage::registry::allocate_code_encrypt_manual_map_failed(
            reinterpret_cast<const std::uint8_t*>(0x1414DCA81ull));
    report_guard_failure(event, detail);
}

void report_guard_init_missing() noexcept {
    static const char* const detail =
        ::makima::storage::registry::
            allocate_check_guard_init_export_not_found_in_mapped_guard_dll(
                0x1414DCAD1ll);
    static const char* const event =
        ::makima::storage::registry::allocate_code_encrypt_guard_init_missing(
            0x1414DCB0Dll);
    report_guard_failure(event, detail);
}

void report_guard_init_exception() noexcept {
    static const char* const detail =
        ::makima::storage::registry::allocate_guard_init_exception_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DCB2Eull));
    static const char* const event =
        ::makima::storage::registry::allocate_code_encrypt_guard_init_exception(
            0x1414DCB5Dll);
    report_guard_failure(event, detail);
}

bool invoke_guard_init(GuardInitFunction init, const GuardHostImageRange* range) noexcept {
#if defined(_MSC_VER)
    __try {
        (void)init(range);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#else
    (void)init(range);
    return true;
#endif
}

}

namespace detail {

namespace {

[[nodiscard]] const char* raw_narrow_string_data(
    const RawNarrowStringOwner& owner) noexcept {
    return owner.capacity < 16 ? owner.text.inline_text : owner.text.heap_text;
}

[[nodiscard]] std::string_view raw_narrow_string_view(
    const RawNarrowStringOwner& owner) noexcept {
    return {raw_narrow_string_data(owner), owner.size};
}

void release_raw_narrow_string_storage(
    RawNarrowStringOwner* owner) noexcept {
    if (owner->capacity < 16) return;

    char* allocation = owner->text.heap_text;
    std::size_t allocation_size = owner->capacity + 1;
    if (allocation_size >= 0x1000) {
        char* original_allocation{};
        std::memcpy(
            &original_allocation,
            allocation - sizeof(original_allocation),
            sizeof(original_allocation));
        const auto alignment_offset =
            static_cast<std::size_t>(allocation - original_allocation);
        if (alignment_offset < sizeof(original_allocation) ||
            alignment_offset > 0x27) {
            _invoke_watson(nullptr, nullptr, nullptr, 0, 0);
        }
        allocation = original_allocation;
        allocation_size += 0x27;
    }
    ::operator delete(allocation, allocation_size);
}

void destroy_security_event_submission_worker_context(
    SecurityEventSubmissionWorkerContext* context) noexcept {
    if (context == nullptr) return;

    release_raw_narrow_string_storage(&context->alternate_document);
    context->alternate_document.size = 0;
    context->alternate_document.capacity = 15;
    context->alternate_document.text.inline_text[0] = '\0';

    release_raw_narrow_string_storage(&context->primary_document);
    ::operator delete(context, sizeof(SecurityEventSubmissionWorkerContext));
}

}







void submit_prebuilt_security_event_documents(
    RawNarrowStringOwner* primary_document,
    RawNarrowStringOwner* alternate_document) {



    auto* bound_client = ::makima::network::session::
        current_authenticated_request_client();
    assert(bound_client != nullptr);
    auto& client = *bound_client;

    const bool session_was_open = client.connected();
    const RawNarrowStringOwner& selected_document =
        session_was_open ? *primary_document : *alternate_document;

    if (!session_was_open) {
        std::array<char, 0x80> identity{};
        if (!::makima::network::session::write_current_user_sid_utf8(
                identity.data(), static_cast<int>(identity.size()))) {
            static const char* const anonymous_identity =
                allocate_anonymous_security_identity();
            const std::string_view anonymous_identity_view{anonymous_identity};
            std::copy(
                anonymous_identity_view.begin(), anonymous_identity_view.end(),
                identity.begin());
        }
        try {



            client.open(identity.data());
        } catch (...) {
            return;
        }
    }

    (void)client.submit_security_event_document(
        raw_narrow_string_view(selected_document));
}




std::uint64_t run_security_event_submission_worker(
    SecurityEventSubmissionWorkerContext* context) {
    submit_prebuilt_security_event_documents(
        &context->primary_document, &context->alternate_document);
    _Cnd_do_broadcast_at_thread_exit();
    destroy_security_event_submission_worker_context(context);
    return 0;
}

}

static std::string hexadecimal(std::uintptr_t value) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result(sizeof(value) * 2U, '0');
    for (std::size_t index = result.size(); index != 0; --index) {
        result[index - 1] = digits[value & 0x0fU];
        value >>= 4U;
    }
    return result;
}

bool capture_process_memory_snapshot_sync() {
    const auto processes = ::makima::platform::ProcessInventory{}.snapshot();
    if (processes.empty()) {


        static const char* const text_crc_mismatch_event =
            ::makima::security::environment::allocate_text_crc_mismatch_event(
                reinterpret_cast<const std::uint8_t*>(0x1414DCA25ull));
        sync_capture_and_report_wrapper(
            text_crc_mismatch_event, 4, "process inventory unavailable");
        return false;
    }
    std::string detail = "{\"process_count\":" + std::to_string(processes.size()) + "}";
    sync_capture_and_report_wrapper("loader.wwinmain_seh", 2, detail.c_str());
    return true;
}








std::uint32_t registry_telemetry_worker(void* context) noexcept {
    (void)context;
    auto& runtime =
        ::makima::storage::registry::registry_telemetry_worker_runtime();

    while (runtime.running) {
        std::int64_t counter{};
        if (runtime.query_counter != nullptr) {
            (void)runtime.query_counter(&counter);
        }

        const std::uint32_t delay =
            static_cast<std::uint32_t>(counter) % 5001U + 3000U;
        for (std::uint32_t elapsed = 0;
             runtime.running && elapsed < delay;
             elapsed += 100U) {
            if (runtime.sleep != nullptr) {
                runtime.sleep(100U);
            }
        }

        if (!runtime.running) return 0;
        if (guard_verify_integrity()) continue;

        static const char* const detail_format =
            ::makima::security::environment::
                allocate_text_section_crc_mismatch_detail_format(
                    reinterpret_cast<const std::uint8_t*>(0x1414DC9DCull));
        std::array<char, 0x100> detail{};
        std::snprintf(
            detail.data(), detail.size(), detail_format,
            guarded_text_size, guarded_text_baseline_crc);

        static const char* const event_name =
            ::makima::security::environment::allocate_text_crc_mismatch_event(
                reinterpret_cast<const std::uint8_t*>(0x1414DCA25ull));
        sync_capture_and_report_wrapper(event_name, 3U, detail.data());
        (void)::TerminateProcess(::GetCurrentProcess(), 0xDEADU);
    }
    return 0;
}

bool schedule_security_capture_async() noexcept {
    if (!capture_process_memory_snapshot_sync()) return false;
    const std::string detail = ::makima::security::environment::collect_host_environment_inventory();
    if (detail.empty()) return false;
    async_capture_and_report_wrapper("security.environment", 2, detail.c_str());
    return true;
}

std::uint64_t report_unauthorized_mapping(
    HANDLE process,
    std::uintptr_t caller,
    std::uintptr_t target,
    std::size_t region_size,
    std::uint64_t allocation_type,
    std::uint64_t protection,
    std::uint64_t mapping_type,
    std::uint32_t process_id,
    std::uint32_t thread_id,
    std::uint32_t status) {
    (void)process;
    (void)target;
    (void)region_size;
    (void)allocation_type;
    (void)mapping_type;
    (void)process_id;
    (void)thread_id;
    (void)status;



    static const char* const detail_format =
        ::makima::security::environment::allocate_unauthorized_mapping_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC79Cull));
    std::array<char, 0x100> formatted{};
    std::snprintf(
        formatted.data(), formatted.size(), detail_format,
        static_cast<unsigned long long>(caller), static_cast<unsigned long>(protection));
    static const char* const event_name =
        ::makima::security::environment::allocate_blocked_mapping_event_name(
            reinterpret_cast<const std::uint8_t*>(0x1414DC7DEull));
    async_capture_and_report_wrapper(
        event_name, 3, formatted.data());
    return 0xC0000022ull;
}

std::uint64_t report_remote_or_executable_thread_start(
    HANDLE process,
    std::uint32_t process_id,
    std::uintptr_t caller,
    std::uintptr_t target,
    std::uint64_t creation_flags) {
    (void)process;
    (void)process_id;



    static const char* const remote_detail_format =
        ::makima::security::environment::allocate_remote_thread_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC7F7ull));
    static const char* const remote_event =
        ::makima::security::environment::allocate_remote_thread_blocked_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC835ull));
    static const char* const executable_detail_format =
        ::makima::security::environment::allocate_rwx_thread_start_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC851ull));
    static const char* const executable_event =
        ::makima::security::environment::allocate_rwx_thread_start_blocked_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC892ull));

    const bool executable_start_path = (creation_flags & 1U) != 0;
    std::array<char, 0x100> formatted{};
    std::snprintf(
        formatted.data(), formatted.size(),
        executable_start_path ? executable_detail_format : remote_detail_format,
        static_cast<unsigned long long>(caller), static_cast<unsigned long long>(target));
    async_capture_and_report_wrapper(
        executable_start_path ? executable_event : remote_event,
        3,
        formatted.data());
    return 0xC0000022ull;
}

std::uint64_t report_executable_text_protection(
    std::uintptr_t caller,
    const std::uintptr_t* target,
    std::size_t region_size,
    std::uint32_t protection) {
    if (target == nullptr) return 0;
    (void)region_size;


    static const char* const detail_format =
        ::makima::security::environment::allocate_rwx_text_protection_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC8AEull));
    static const char* const event =
        ::makima::security::environment::allocate_blocked_protect_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC8FDull));
    std::array<char, 0x100> formatted{};
    std::snprintf(
        formatted.data(), formatted.size(), detail_format,
        static_cast<unsigned long long>(caller),
        static_cast<unsigned long long>(*target),
        static_cast<unsigned long>(protection));
    async_capture_and_report_wrapper(event, 3, formatted.data());
    return 0xC0000022ull;
}

std::uint64_t report_external_thread_suspend(std::uintptr_t caller, std::uintptr_t target) {




    static const char* const external_detail_format =
        ::makima::security::environment::allocate_external_suspend_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC91Aull));
    static const char* const external_event =
        ::makima::security::environment::allocate_blocked_suspend_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC94Aull));
    static const char* const thread_detail_format =
        ::makima::security::environment::allocate_thread_suspend_detail_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC967ull));
    static const char* const thread_event =
        ::makima::security::environment::allocate_suspect_suspend_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC9A0ull));

    const bool current_thread_path = target != 0;
    std::array<char, 0x100> formatted{};
    if (current_thread_path) {


        std::snprintf(
            formatted.data(), 0x80, thread_detail_format,
            static_cast<unsigned long long>(caller),
            static_cast<unsigned long long>(target));
    } else {


        std::snprintf(
            formatted.data(), formatted.size(), external_detail_format,
            static_cast<unsigned long long>(caller));
    }
    async_capture_and_report_wrapper(
        current_thread_path ? thread_event : external_event,
        current_thread_path ? 2U : 3U,
        formatted.data());
    return current_thread_path ? 1U : 0xC0000022ull;
}

bool schedule_integrity_capture_async(char* raw_state) noexcept {
    auto* state = reinterpret_cast<GuardCaptureState*>(raw_state);
    if (state->initialized != 0) return true;

    try {
        const auto mapped = ::makima::process::pe_mapping::manual_map_pe_dll(
            GetCurrentProcessId(),
            std::span<const std::uint8_t>{
                detail::embedded_guard_image.data(), detail::embedded_guard_image.size()});
        if (mapped.image_base == 0 || !mapped.entry_point_succeeded) {
            report_guard_mapping_failure();
            return false;
        }

        state->mapped_guard_image = mapped.image_base;
        const ::makima::process::pe_mapping::RemoteModule guard_module{
            mapped.image_base, 0xe000U, L"makima-guard.dll", L"<manual-map>"};
        const auto process_id = GetCurrentProcessId();
        static const char* const guard_init_export =
            ::makima::storage::registry::allocate_guard_init(
                reinterpret_cast<const std::byte*>(0x1414DCAA1ull));
        const auto init = reinterpret_cast<GuardInitFunction>(
            ::makima::process::pe_mapping::resolve_remote_export(
                process_id, guard_module, guard_init_export));
        static const char* const guard_shutdown_export =
            ::makima::storage::registry::allocate_guard_shutdown_export(
                reinterpret_cast<const std::uint8_t*>(0x1414DCAACull));
        ::makima::storage::registry::guard_shutdown_callback =
            reinterpret_cast<GuardShutdownFunction>(
            ::makima::process::pe_mapping::resolve_remote_export(
                process_id, guard_module, guard_shutdown_export));
        static const char* const guard_verify_integrity_export =
            ::makima::storage::registry::allocate_guard_verify_integrity(
                0x1414DCABBll);
        guard_verify_integrity = reinterpret_cast<GuardVerifyIntegrityFunction>(
            ::makima::process::pe_mapping::resolve_remote_export(
                process_id, guard_module, guard_verify_integrity_export));
        if (init == nullptr) {
            report_guard_init_missing();
            return false;
        }

        GuardHostImageRange host_image{};
        if (!get_host_image_range(&host_image)) {
            report_guard_init_exception();
            return false;
        }
        if (!invoke_guard_init(init, &host_image)) {
            report_guard_init_exception();
            return false;
        }
        state->initialized = 1;
        return true;
    } catch (const ::makima::process::pe_mapping::MappingError&) {
        report_guard_mapping_failure();
        return false;
    } catch (...) {
        report_guard_init_exception();
        return false;
    }
}

}
