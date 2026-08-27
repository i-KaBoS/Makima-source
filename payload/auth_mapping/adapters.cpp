#include "payload/auth_mapping/auth_mapping.hpp"

#include <cstdlib>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <new>
#include <string_view>
#include <utility>
#include <windows.h>

namespace makima::payload::auth_mapping {

namespace {

FARPROC shell_execute_w_import{};

char* allocate_import_name(std::string_view name) {
    auto* output = static_cast<char*>(::operator new(name.size() + 1U));
    std::memcpy(output, name.data(), name.size());
    output[name.size()] = '\0';
    return output;
}


char* allocate_return_check_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("callsite-5 is E9 (JMP) caller was hooked");
}


char* allocate_trampoline_check_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("callsite preceded by neither E8 nor FF /2");
}


char* allocate_opcode_check_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("RSP is outside the TEB-reported stack bounds");
}

constexpr std::uintptr_t kMappingResultBaseVtable = 0x14149E480ull;
constexpr std::uintptr_t kPrimaryMappingResultVtable = 0x14149E4B0ull;
constexpr std::uintptr_t kSecondaryMappingResultVtable = 0x14149E498ull;

void copy_owned_narrow_string_state(
    const OwnedNarrowStringState& source,
    OwnedNarrowStringState& destination) noexcept {
    if (!source.owns_data || source.data == nullptr) {
        destination.data = source.data;
        destination.owns_data = false;
        return;
    }

    const std::size_t byte_count = std::strlen(source.data) + 1U;
    auto* copied_data = static_cast<char*>(std::malloc(byte_count));
    if (copied_data != nullptr) {
        std::memcpy(copied_data, source.data, byte_count);
        destination.data = copied_data;
        destination.owns_data = true;
    }
}

}



void bind_shell_execute_w() noexcept {
    const HMODULE module = LoadLibraryA("shell32.dll");
    shell_execute_w_import = module == nullptr
        ? nullptr
        : GetProcAddress(module, "ShellExecuteW");
}




void release_owned_narrow_string_state(
    OwnedNarrowStringState& state) noexcept {
    if (state.owns_data) {
        std::free(state.data);
    }
    state.owns_data = false;
    state.data = nullptr;
}



char* allocate_create_file_mapping_w_import(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("CreateFileMappingW");
}



char* allocate_kernel32_for_map_view_of_file(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("kernel32.dll");
}



char* allocate_kernel32_for_unmap_view_of_file(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_import_name("kernel32.dll");
}




int scan_mapping_text(
    const char* input,
    const char* format,
    ...) noexcept {
    std::va_list arguments;
    va_start(arguments, format);
    const int result = std::vsscanf(input, format, arguments);
    va_end(arguments);
    return result;
}






const char* return_address_outside_text_detail() noexcept {
    static const char* value = allocate_return_text_section_detail(
        0x1414D8A31ll);
    return value;
}


const char* return_address_outside_text_event() noexcept {
    static const char* value = allocate_return_address_outside_text_finding(
        0x1414D8A63ll);
    return value;
}


const char* jump_trampoline_at_callsite_event() noexcept {
    static const char* value = allocate_callsite_trampoline_finding(
        0x1414D8AB6ll);
    return value;
}


const char* callsite_not_call_opcode_event() noexcept {
    static const char* value = allocate_invalid_callsite_opcode_finding(
        0x1414D8B09ll);
    return value;
}



const char* return_address_diagnostic_format() {
    static const char* value = allocate_return_check_format(
        reinterpret_cast<const std::uint8_t*>(0x1414D8A8Cull));
    return value;
}



const char* trampoline_diagnostic_format() {
    static const char* value = allocate_trampoline_check_format(
        reinterpret_cast<const std::uint8_t*>(0x1414D8ADEull));
    return value;
}



const char* call_opcode_diagnostic_format() {
    static const char* value = allocate_opcode_check_format(
        reinterpret_cast<const std::uint8_t*>(0x1414D8B2Full));
    return value;
}


const char* stack_pointer_out_of_bounds_event() noexcept {
    static const char* value = allocate_stack_pointer_bounds_finding(
        0x1414D8B5Dll);
    return value;
}


const char* parent_return_outside_text_detail() noexcept {
    static const char* value = allocate_parent_return_address_detail(
        0x1414D8B7Cll);
    return value;
}


const char* parent_return_outside_text_event() noexcept {
    static const char* value = allocate_parent_return_address_finding(
        0x1414D8BAFll);
    return value;
}



PolymorphicNarrowStringOwner* copy_owned_narrow_string_into_primary_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept {
    destination->vtable = kMappingResultBaseVtable;
    destination->text = {};
    copy_owned_narrow_string_state(source->text, destination->text);
    destination->vtable = kPrimaryMappingResultVtable;
    return destination;
}



PolymorphicNarrowStringOwner* copy_owned_narrow_string_into_secondary_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept {
    destination->vtable = kMappingResultBaseVtable;
    destination->text = {};
    copy_owned_narrow_string_state(source->text, destination->text);
    destination->vtable = kSecondaryMappingResultVtable;
    return destination;
}




PolymorphicNarrowStringOwner* copy_owned_narrow_string_into_base_variant(
    PolymorphicNarrowStringOwner* destination,
    const PolymorphicNarrowStringOwner* source) noexcept {
    destination->vtable = kMappingResultBaseVtable;
    destination->text = {};
    copy_owned_narrow_string_state(source->text, destination->text);
    return destination;
}



PolymorphicNarrowStringOwner* initialize_mapping_result_base_vtable(
    PolymorphicNarrowStringOwner* owner) noexcept {
    owner->vtable = kMappingResultBaseVtable;
    return owner;
}

bool constant_time_equal(
    std::span<const std::byte> left,
    std::span<const std::byte> right) noexcept {
    if (left.size() != right.size() || left.empty()) return false;
    std::uint8_t difference = 0;
    for (std::size_t index = 0; index < left.size(); ++index) {
        difference |= static_cast<std::uint8_t>(left[index] ^ right[index]);
    }
    return difference == 0;
}

}
