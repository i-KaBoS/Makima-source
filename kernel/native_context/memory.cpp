#include "kernel/native_context/native_context.hpp"

#include <cstring>
#include <new>

namespace makima::kernel::native_context {
namespace {

template <std::size_t Extent>
[[nodiscard]] wchar_t* allocate_wide_literal(
    const wchar_t (&literal)[Extent]) {
    static_assert(sizeof(wchar_t) == sizeof(std::uint16_t));
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}

template <std::size_t Extent>
[[nodiscard]] char* allocate_narrow_literal(const char (&literal)[Extent]) {
    auto* output = static_cast<char*>(::operator new(sizeof(literal)));
    std::memcpy(output, literal, sizeof(literal));
    return output;
}

}





wchar_t* allocate_se_impersonate_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"SeImpersonatePrivilege");
}



wchar_t* allocate_se_debug_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"SeDebugPrivilege");
}



wchar_t* allocate_schedule_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"Schedule");
}



wchar_t* allocate_se_tcb_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"SeTcbPrivilege");
}





wchar_t* allocate_se_lock_memory_privilege(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal(L"SeLockMemoryPrivilege");
}




char* allocate_ntoskrnl_image_name(const std::byte* protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("ntoskrnl.exe");
}




char* allocate_ksecdd_driver_name(const std::byte* protected_source) {
    (void)protected_source;
    return allocate_narrow_literal("ksecdd.sys");
}

}
