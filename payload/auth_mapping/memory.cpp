#include "payload/auth_mapping/auth_mapping.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <string_view>

namespace makima::payload::auth_mapping {

namespace {

char* allocate_persistent_ansi(std::string_view value) {
    auto* storage = new char[value.size() + 1U];
    std::memcpy(storage, value.data(), value.size());
    storage[value.size()] = '\0';
    return storage;
}

}

[[nodiscard]] bool copy_authenticated_bytes(
    const AuthenticatedImage& image,
    std::span<std::byte> destination) noexcept {
    if (!image.authenticated || destination.size() < image.bytes.size()) return false;
    std::copy(image.bytes.begin(), image.bytes.end(), destination.begin());
    return true;
}



std::uint64_t release_mapping_request_state(std::string& state) noexcept {
    std::string{}.swap(state);
    return 0xe314694e53fc5c36ull;
}



void release_mapping_payload_owner(MappingPayloadOwner& owner) noexcept {
    std::string{}.swap(owner.request_state);
    std::vector<std::byte>{}.swap(owner.bytes);
}



void release_mapping_record_range(
    std::vector<std::array<std::byte, 16>>& records) noexcept {
    std::vector<std::array<std::byte, 16>>{}.swap(records);
}




PolymorphicNarrowStringOwner* destroy_secondary_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept {
    owner->vtable = 0x14149E480ull;
    release_owned_narrow_string_state(owner->text);
    if (deletion_flag != 0U) {
        ::operator delete(owner, sizeof(PolymorphicNarrowStringOwner));
    }
    return owner;
}




PolymorphicNarrowStringOwner* destroy_primary_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept {
    owner->vtable = 0x14149E480ull;
    release_owned_narrow_string_state(owner->text);
    if (deletion_flag != 0U) {
        ::operator delete(owner, sizeof(PolymorphicNarrowStringOwner));
    }
    return owner;
}






char* allocate_return_text_section_detail(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "_ReturnAddress() is not inside our .text section");
}


char* allocate_return_address_outside_text_finding(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "anti_tamper.return_address_outside_text");
}


char* allocate_callsite_trampoline_finding(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "anti_tamper.jmp_trampoline_at_callsite");
}


char* allocate_invalid_callsite_opcode_finding(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "anti_tamper.callsite_not_call_opcode");
}


char* allocate_stack_pointer_bounds_finding(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("anti_tamper.rsp_out_of_bounds");
}


char* allocate_parent_return_address_detail(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "parent stack frame return address is not in .text");
}


char* allocate_parent_return_address_finding(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi(
        "anti_tamper.parent_return_outside_text");
}


char* allocate_mapping_kernel_module_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("kernel32.dll");
}


char* allocate_map_view_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("MapViewOfFile");
}


char* allocate_unmap_view_api_name(std::int64_t protected_source) {
    (void)protected_source;
    return allocate_persistent_ansi("UnmapViewOfFile");
}

}
