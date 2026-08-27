#include "kernel/silo/silo.hpp"

#include <windows.h>
#include <winternl.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <vector>

namespace makima::kernel::silo {

namespace {

struct ExtendedHandleEntry final {
    void* object;
    std::uintptr_t process_id;
    std::uintptr_t handle_value;
    std::uint32_t granted_access;
    std::uint16_t creator_backtrace_index;
    std::uint16_t object_type_index;
    std::uint32_t handle_attributes;
    std::uint32_t reserved;
};

static_assert(sizeof(ExtendedHandleEntry) == 0x28);

}




void* resolve_system_process_object(SystemProcessObjectCache* context) {
    if (context->cached_system_process_object != nullptr) {
        return context->cached_system_process_object;
    }

    constexpr std::size_t kQueryBytes = 0x02000000;
    constexpr std::size_t kAllocationBytes = kQueryBytes + 0x27;
    auto* allocation = static_cast<std::byte*>(::operator new(kAllocationBytes));
    const auto aligned_address =
        (reinterpret_cast<std::uintptr_t>(allocation) + 0x27U) &
        ~std::uintptr_t{0x1fU};
    auto* query_buffer = reinterpret_cast<std::byte*>(aligned_address);
    reinterpret_cast<void**>(query_buffer)[-1] = allocation;
    std::memset(query_buffer, 0, kQueryBytes);

    (void)::NtQuerySystemInformation(
        static_cast<SYSTEM_INFORMATION_CLASS>(0x40),
        query_buffer,
        static_cast<ULONG>(kQueryBytes),
        nullptr);

    const auto handle_count =
        *reinterpret_cast<const std::uintptr_t*>(query_buffer);
    const auto* entries = reinterpret_cast<const ExtendedHandleEntry*>(
        query_buffer + 0x10);
    constexpr std::size_t kMaximumEntries =
        (kQueryBytes - 0x10) / sizeof(ExtendedHandleEntry);
    const auto bounded_count =
        (handle_count < kMaximumEntries) ? handle_count : kMaximumEntries;
    for (std::size_t index = 0; index < bounded_count; ++index) {
        if (entries[index].process_id == 4U) {
            context->cached_system_process_object = entries[index].object;
            break;
        }
    }

    ::operator delete(reinterpret_cast<void**>(query_buffer)[-1]);
    return context->cached_system_process_object;
}



SiloRecord make_silo_record(
    std::span<const std::byte> payload,
    std::uint64_t record_key) {
    SiloRecord record;
    record.key = record_key;
    record.value = hash_silo_payload(payload, record_key);
    record.flags = payload.empty() ? 0U : 1U;
    record.payload.assign(payload.begin(), payload.end());
    return record;
}



SiloRecord make_tagged_silo_record(
    std::span<const std::byte> payload,
    std::uint64_t record_key) {
    auto record = make_silo_record(payload, record_key);
    record.value = derive_ksec_request_tag(record.value, record_key);
    record.flags |= 2U;
    return record;
}



void xor_silo_payload(
    std::span<std::byte> payload,
    std::uint64_t xor_key) noexcept {
    for (std::size_t byte_index = 0; byte_index < payload.size(); ++byte_index) {
        const auto key_byte = static_cast<std::uint8_t>(
            xor_key >> ((byte_index & 7U) * 8U));
        payload[byte_index] ^= static_cast<std::byte>(key_byte);
    }
}



std::wstring utf16_text_from_little_endian_bytes(
    std::span<const std::byte> payload) {
    if ((payload.size() & 1U) != 0) {
        throw_buffer_bounds_error();
    }
    std::wstring decoded_text;
    decoded_text.reserve(payload.size() / 2U);
    for (std::size_t offset = 0; offset < payload.size(); offset += 2U) {
        const auto low = std::to_integer<std::uint8_t>(payload[offset]);
        const auto high = std::to_integer<std::uint8_t>(payload[offset + 1U]);
        const auto character = static_cast<wchar_t>(low | (static_cast<std::uint16_t>(high) << 8U));
        if (character == L'\0') {
            break;
        }
        decoded_text.push_back(character);
    }
    return decoded_text;
}





bool record_payload_equals(
    const SiloRecord& record,
    std::span<const std::byte> expected) noexcept {
    if (record.payload.size() != expected.size()) {
        return false;
    }
    std::uint8_t accumulated_difference = 0;
    for (std::size_t byte_index = 0; byte_index < expected.size(); ++byte_index) {
        accumulated_difference |= std::to_integer<std::uint8_t>(
            record.payload[byte_index] ^ expected[byte_index]);
    }
    return accumulated_difference == 0;
}

}
