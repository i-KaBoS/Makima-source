#include <array>
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <string>

#include "kernel/symbols/symbols.hpp"
#include "ui/webview2_runtime.hpp"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>
#include <utility>

#include <windows.h>

extern "C" void __cdecl _Cnd_do_broadcast_at_thread_exit();
extern "C" [[noreturn]] void __cdecl _invoke_watson(
    const wchar_t* expression,
    const wchar_t* function_name,
    const wchar_t* file_name,
    unsigned int line_number,
    std::uintptr_t reserved);

namespace makima::kernel::symbols {

namespace {

struct SymbolByteRange {
    std::byte* begin;
    std::byte* end;
    std::byte* capacity;
};
static_assert(sizeof(SymbolByteRange) == 0x18);

std::byte* allocate_symbol_storage(std::size_t size) {
    constexpr std::size_t large_allocation_threshold = 0x1000;
    constexpr std::size_t alignment = 0x20;
    constexpr std::size_t alignment_overhead = alignment + sizeof(void*) - 1;
    if (size < large_allocation_threshold) {
        return static_cast<std::byte*>(::operator new(size));
    }
    if (size > static_cast<std::size_t>(-1) - alignment_overhead) {
        throw std::bad_array_new_length{};
    }
    auto* allocation = static_cast<std::byte*>(
        ::operator new(size + alignment_overhead));
    const auto aligned_address =
        (reinterpret_cast<std::uintptr_t>(allocation) + alignment_overhead) &
        ~(static_cast<std::uintptr_t>(alignment) - 1U);
    auto* aligned = reinterpret_cast<std::byte*>(aligned_address);
    std::memcpy(aligned - sizeof(void*), &allocation, sizeof(allocation));
    return aligned;
}

char* allocate_persistent_symbol_message(std::string_view value) {
    auto* const output = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return output;
}

void release_symbol_storage(
    std::byte* begin,
    std::byte* capacity) noexcept {
    if (begin == nullptr) return;
    constexpr std::size_t large_allocation_threshold = 0x1000;
    constexpr std::size_t maximum_alignment_offset = 0x27;
    void* allocation = begin;
    const auto size = static_cast<std::size_t>(capacity - begin);
    if (size >= large_allocation_threshold) {
        std::byte* original{};
        std::memcpy(&original, begin - sizeof(void*), sizeof(original));
        const auto offset = static_cast<std::size_t>(begin - original);
        if (offset < sizeof(void*) || offset > maximum_alignment_offset) {
            _invoke_watson(nullptr, nullptr, nullptr, 0, 0);
        }
        allocation = original;
    }
    ::operator delete(allocation);
}

void release_context_pointer(
    std::int64_t context,
    std::size_t allocation_size) noexcept {
    void* pointer{};
    std::memcpy(&pointer, reinterpret_cast<const void*>(context + 0x1b0),
                sizeof(pointer));
    if (pointer != nullptr) ::operator delete(pointer, allocation_size);
}

}








void reset_owned_wide_symbol_text(OwnedWideSymbolText* owner) noexcept {
    if (owner->capacity >= 8) {
        wchar_t* payload = owner->text.heap_text;
        void* allocation = payload;
        const std::size_t allocation_bytes =
            (owner->capacity + 1) * sizeof(wchar_t);

        if (allocation_bytes >= 0x1000) {
            wchar_t* original_allocation{};
            std::memcpy(
                &original_allocation,
                reinterpret_cast<const std::byte*>(payload) -
                    sizeof(original_allocation),
                sizeof(original_allocation));
            const auto alignment_offset =
                reinterpret_cast<const std::byte*>(payload) -
                reinterpret_cast<const std::byte*>(original_allocation);
            if (alignment_offset < 8 || alignment_offset > 0x27) {
                _invoke_watson(nullptr, nullptr, nullptr, 0, 0);
            }
            allocation = original_allocation;
        }

        std::free(allocation);
    }

    owner->size = 0;
    owner->capacity = 7;
    owner->text.inline_text[0] = L'\0';
}







SymbolByteRange* release_symbol_byte_range(SymbolByteRange* range) noexcept {
    if (range->begin == nullptr) return nullptr;
    release_symbol_storage(range->begin, range->capacity);
    range->begin = nullptr;
    range->end = nullptr;
    range->capacity = nullptr;
    return range;
}


void release_symbol_scratch_a8(
    std::uint64_t callback_state, std::int64_t context) noexcept {
    (void)callback_state;
    release_context_pointer(context, 0xa8);
}


void release_symbol_scratch_78_primary(
    std::uint64_t callback_state, std::int64_t context) noexcept {
    (void)callback_state;
    release_context_pointer(context, 0x78);
}


void release_symbol_scratch_78_secondary(
    std::uint64_t callback_state, std::int64_t context) noexcept {
    (void)callback_state;
    release_context_pointer(context, 0x78);
}



SymbolByteRange* allocate_zeroed_symbol_byte_range(
    SymbolByteRange* range, std::uint64_t size) {
    range->begin = nullptr;
    range->end = nullptr;
    range->capacity = nullptr;
    if (size == 0) return range;
    auto* memory = allocate_symbol_storage(static_cast<std::size_t>(size));
    std::memset(memory, 0, static_cast<std::size_t>(size));
    range->begin = memory;
    range->end = memory + size;
    range->capacity = memory + size;
    return range;
}




std::string* format_symbol_identity(
    std::string* output,
    const std::byte* identity,
    std::uint32_t trailing_word) {
    std::array<char, 0x40> text{};
    _snprintf_s(
        text.data(), text.size(), _TRUNCATE,
        "%02X%02X%02X%02X%02X%02X%02X%02X"
        "%02X%02X%02X%02X%02X%02X%02X%02X%X",
        std::to_integer<unsigned>(identity[3]),
        std::to_integer<unsigned>(identity[2]),
        std::to_integer<unsigned>(identity[1]),
        std::to_integer<unsigned>(identity[0]),
        std::to_integer<unsigned>(identity[5]),
        std::to_integer<unsigned>(identity[4]),
        std::to_integer<unsigned>(identity[7]),
        std::to_integer<unsigned>(identity[6]),
        std::to_integer<unsigned>(identity[8]),
        std::to_integer<unsigned>(identity[9]),
        std::to_integer<unsigned>(identity[10]),
        std::to_integer<unsigned>(identity[11]),
        std::to_integer<unsigned>(identity[12]),
        std::to_integer<unsigned>(identity[13]),
        std::to_integer<unsigned>(identity[14]),
        std::to_integer<unsigned>(identity[15]),
        trailing_word);
    *output = text.data();
    return output;
}





std::byte* decode_protected_bytes_140642640(
    std::int64_t source) {
    const auto* input = reinterpret_cast<const std::byte*>(source);
    auto* output = static_cast<std::byte*>(::operator new(19));

    const auto value = [input](std::size_t index) noexcept {
        return std::to_integer<std::uint8_t>(input[index]);
    };
    const auto rotate_left = [](std::uint8_t byte, unsigned count) noexcept {
        return static_cast<std::uint8_t>(
            (byte << count) | (byte >> (8U - count)));
    };
    const auto store = [output](std::size_t index, std::uint8_t byte) noexcept {
        output[index] = static_cast<std::byte>(byte);
    };

    store(0, static_cast<std::uint8_t>(rotate_left(value(0) ^ 0x25U, 4) + 0x52U));
    store(1, static_cast<std::uint8_t>(rotate_left(value(1) ^ 0x87U, 4) + 0x61U));
    store(2, static_cast<std::uint8_t>(rotate_left(value(2) ^ 0x61U, 4) + 0x34U));
    store(3, static_cast<std::uint8_t>(rotate_left(value(3) ^ 0xD2U, 4) + 0xDFU));
    store(4, static_cast<std::uint8_t>(rotate_left(value(4) ^ 0xA5U, 4) + 0x16U));
    store(5, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>(0x75U - (value(5) ^ 0x3BU)), 1) ^ 0x78U));
    store(6, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>((value(6) ^ 0x33U) + 0x04U), 1) ^ 0x08U));
    store(7, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>(0x38U - (value(7) ^ 0x34U)), 1) ^ 0x36U));
    store(8, static_cast<std::uint8_t>(rotate_left(value(8) ^ 0xC9U, 5) + 0x59U));
    store(9, static_cast<std::uint8_t>(rotate_left(value(9) ^ 0xA3U, 5) + 0x3AU));
    store(10, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>(value(10) + 0x38U), 2) ^ 0x2CU));
    store(11, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>(0x64U - (value(11) ^ 0x28U)), 2) ^ 0x68U));
    store(12, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>((value(12) ^ 0x10U) + 0x23U), 2) ^ 0x2DU));
    store(13, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>((value(13) ^ 0x2FU) + 0x98U), 2) ^ 0x01U));
    store(14, static_cast<std::uint8_t>(rotate_left(value(14) ^ 0x19U, 5) + 0xE6U));
    store(15, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>(0x51U - (value(15) ^ 0x1DU)), 2) ^ 0x58U));
    store(16, static_cast<std::uint8_t>(
        rotate_left(static_cast<std::uint8_t>((value(16) ^ 0x3CU) + 0x0FU), 7) ^ 0x01U));
    store(17, static_cast<std::uint8_t>(rotate_left(value(17) ^ 0xD5U, 2) + 0xB7U));
    output[18] = std::byte{};
    return output;
}







std::uint64_t run_delayed_navigation_reveal(void** context) noexcept {
    auto* const window_state = static_cast<std::byte*>(*context);
    ::Sleep(2000);

    HWND window{};
    std::memcpy(&window, window_state + 0x08, sizeof(window));
    if (window != nullptr &&
        window_state[0x34] == std::byte{} &&
        window_state[0x36] == std::byte{}) {
        makima::ui::reveal_window_after_navigation(window);
    }

    _Cnd_do_broadcast_at_thread_exit();
    ::operator delete(context, sizeof(void*));
    return 0;
}



wchar_t* allocate_services_active_database_name(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ServicesActive";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_microsoft_symbol_server_host_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"msdl.microsoft.com";
    static_assert(sizeof(value) == 38U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_winhttp_connect_failure_message(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("WinHttpConnect failed");
}


char* allocate_pdb_stream_too_small_for_guid_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "stream 1 too small for GUID check");
}


char* allocate_pdb_guid_mismatch_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("PDB GUID mismatch");
}




char* allocate_dbi_stream_too_small_message(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("DBI stream too small");
}


char* allocate_dbi_symbol_record_stream_index_invalid_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "DBI sym_record_stream index invalid");
}


char* allocate_optional_debug_header_overflow_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "OptionalDbgHeader overflows DBI stream");
}


char* allocate_optional_debug_header_too_small_for_section_header_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "OptionalDbgHeader too small for section header entry");
}


char* allocate_section_header_stream_index_invalid_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "section header stream index invalid");
}


char* allocate_section_header_stream_empty_or_too_small_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "section header stream empty or too small");
}


char* allocate_symbol_record_stream_empty_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("symbol record stream empty");
}


char* allocate_no_symbols_found_in_symbol_record_stream_message(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message(
        "no symbols found in symbol record stream");
}


char* allocate_dbi_symbol_parse_failure_prefix(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("DBI/symbol parse failed: ");
}


char* allocate_tpi_stream_two_empty_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("stream 2 empty");
}


char* allocate_tpi_header_too_small_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("TPI header too small");
}


char* allocate_bad_tpi_header_size_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("bad TPI HeaderSize");
}


char* allocate_tpi_records_overflow_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("TPI records overflow");
}


char* allocate_tpi_index_range_invalid_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("TPI index range invalid");
}


char* allocate_tpi_record_truncated_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("TPI record truncated");
}


char* allocate_dbgkp_triage_dump_save_state_export_name(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("DbgkpTriageDumpSaveState");
}


char* allocate_dbgkp_triage_dump_restore_state_export_name(
    std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("DbgkpTriageDumpRestoreState");
}


char* allocate_kernel_base_zero_message(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_symbol_message("kernel_base is zero");
}

}
