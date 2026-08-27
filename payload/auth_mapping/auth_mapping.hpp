#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <span>
#include <string>
#include <vector>

namespace makima::payload::auth_mapping {

[[nodiscard]] char* allocate_return_text_section_detail(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_return_address_outside_text_finding(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_callsite_trampoline_finding(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_invalid_callsite_opcode_finding(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_stack_pointer_bounds_finding(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_parent_return_address_detail(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_parent_return_address_finding(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_mapping_kernel_module_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_map_view_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_unmap_view_api_name(
    std::int64_t protected_source);
[[nodiscard]] char* allocate_create_file_mapping_w_import(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_map_view_of_file(
    const std::uint8_t* protected_source);
[[nodiscard]] char* allocate_kernel32_for_unmap_view_of_file(
    const std::uint8_t* protected_source);
void bind_shell_execute_w() noexcept;

struct MappingPolicy {
    std::size_t maximum_image_size{128U * 1024U * 1024U};
    bool require_pe_image{true};
};

struct AuthenticatedImage {
    std::vector<std::byte> bytes;
    std::uint64_t fingerprint{};
    bool authenticated{};
};



struct MappingPayloadOwner {
    std::uintptr_t vtable{};
    std::vector<std::byte> bytes;
    std::string request_state;
};

static_assert(offsetof(MappingPayloadOwner, bytes) == 0x08);
static_assert(offsetof(MappingPayloadOwner, request_state) == 0x20);



struct OwnedNarrowStringState {
    char* data{};
    bool owns_data{};
    std::byte reserved[7]{};
};

struct PolymorphicNarrowStringOwner {
    std::uintptr_t vtable{};
    OwnedNarrowStringState text{};
};

static_assert(sizeof(OwnedNarrowStringState) == 0x10);
static_assert(offsetof(PolymorphicNarrowStringOwner, text) == 0x08);
static_assert(sizeof(PolymorphicNarrowStringOwner) == 0x18);

[[nodiscard]] PolymorphicNarrowStringOwner*
copy_owned_narrow_string_into_primary_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept;
[[nodiscard]] PolymorphicNarrowStringOwner*
copy_owned_narrow_string_into_secondary_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept;
[[nodiscard]] PolymorphicNarrowStringOwner*
copy_owned_narrow_string_into_base_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept;
[[nodiscard]] PolymorphicNarrowStringOwner*
initialize_mapping_result_base_vtable(
    PolymorphicNarrowStringOwner* owner) noexcept;

void release_owned_narrow_string_state(
    OwnedNarrowStringState& state) noexcept;





[[nodiscard]] PolymorphicNarrowStringOwner* destroy_base_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept;
[[nodiscard]] PolymorphicNarrowStringOwner* destroy_secondary_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept;
[[nodiscard]] PolymorphicNarrowStringOwner* destroy_primary_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept;

[[nodiscard]] void* resolve_ascii_folded_mapping_module_and_exact_export(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_case_folded_mapping_library_and_verbatim_symbol(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_lowercase_mapping_module_hash_and_export_hash(
    const char* module_name,
    const char* export_name) noexcept;
[[nodiscard]] void* resolve_normalized_mapping_library_and_exact_symbol(
    const char* module_name,
    const char* export_name) noexcept;

[[nodiscard]] bool constant_time_equal(
    std::span<const std::byte> left,
    std::span<const std::byte> right) noexcept;
[[nodiscard]] std::uint64_t payload_fingerprint(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] std::span<const std::byte> authenticated_bytes(
    const AuthenticatedImage& image) noexcept;
[[nodiscard]] bool has_valid_pe_layout(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] bool map_authenticated_image(
    std::span<const std::byte> image,
    std::span<const std::byte> supplied_tag,
    std::span<const std::byte> expected_tag,
    const MappingPolicy& policy,
    AuthenticatedImage& result) noexcept;
void clear_authenticated_image(AuthenticatedImage& image) noexcept;

[[nodiscard]] bool mapping_token_equals(
    const std::string& stored,
    const char* token) noexcept;
[[nodiscard]] bool mapping_token_contains_from(
    const std::string& stored,
    const char* token,
    std::size_t start) noexcept;
[[nodiscard]] std::uint64_t release_mapping_request_state(
    std::string& state) noexcept;
void release_mapping_payload_owner(MappingPayloadOwner& owner) noexcept;
void release_mapping_record_range(
    std::vector<std::array<std::byte, 16>>& records) noexcept;
int scan_mapping_text(
    const char* input,
    const char* format,
    ...) noexcept;



void resolve_create_file_mapping_import() noexcept;
void resolve_map_view_of_file_import() noexcept;
void resolve_unmap_view_of_file_import() noexcept;

}
