#include "security/anti_analysis/anti_analysis.hpp"

#include <windows.h>

namespace makima::security::anti_analysis {

namespace {

decltype(&FlushInstructionCache) flush_instruction_cache{};
decltype(&GetTickCount) get_tick_count{};
decltype(&GetThreadContext) get_thread_context{};
decltype(&CheckRemoteDebuggerPresent) check_remote_debugger_present{};
decltype(&QueryFullProcessImageNameW) query_full_process_image_name{};

HMODULE kernel32_module() noexcept {
    return GetModuleHandleW(L"kernel32.dll");
}

}




void allocate_readwrite_region_descriptor(
    std::uintptr_t caller_context,
    std::uintptr_t* descriptor,
    std::size_t requested_size) noexcept {
    (void)caller_context;
    descriptor[0] = reinterpret_cast<std::uintptr_t>(
        ::VirtualAlloc(
            nullptr,
            requested_size,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE));
    descriptor[2] = requested_size;
    descriptor[1] = 0;
}




void finalize_executable_region_descriptor(
    std::uintptr_t caller_context,
    const std::uintptr_t* descriptor) noexcept {
    (void)caller_context;
    DWORD previous_protection = 0;
    ::VirtualProtect(
        reinterpret_cast<void*>(descriptor[0]),
        descriptor[2],
        PAGE_EXECUTE_READ,
        &previous_protection);
    ::FlushInstructionCache(
        ::GetCurrentProcess(),
        reinterpret_cast<const void*>(descriptor[0]),
        descriptor[1]);
}





std::uint64_t current_process_has_no_remote_debugger() noexcept {
    BOOL debugger_present = FALSE;
    const BOOL query_succeeded =
        ::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &debugger_present);
    return query_succeeded == FALSE || debugger_present == FALSE ? 1U : 0U;
}





std::uint64_t current_process_debug_flags_allow_execution() noexcept {
    using NtQueryInformationProcess = LONG (NTAPI*)(
        HANDLE process,
        ULONG process_information_class,
        void* process_information,
        ULONG process_information_length,
        ULONG* return_length);

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_process_information =
        ntdll == nullptr ? nullptr :
        reinterpret_cast<NtQueryInformationProcess>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query_process_information == nullptr) {
        return 1U;
    }

    ULONG debug_flags = 0;
    const LONG status = query_process_information(
        ::GetCurrentProcess(),
        0x1FU,
        &debug_flags,
        sizeof(debug_flags),
        nullptr);
    return (static_cast<ULONG>(status) | debug_flags) != 0U ? 1U : 0U;
}




std::uint64_t current_process_has_no_debug_object() noexcept {
    using NtQueryInformationProcess = LONG (NTAPI*)(
        HANDLE process,
        ULONG process_information_class,
        void* process_information,
        ULONG process_information_length,
        ULONG* return_length);

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto query_process_information =
        ntdll == nullptr ? nullptr :
        reinterpret_cast<NtQueryInformationProcess>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));
    if (query_process_information == nullptr) {
        return 1U;
    }

    HANDLE debug_object = nullptr;
    const LONG status = query_process_information(
        ::GetCurrentProcess(),
        0x1EU,
        &debug_object,
        sizeof(debug_object),
        nullptr);
    return status != 0 || debug_object == nullptr ? 1U : 0U;
}



void bind_flush_instruction_cache() noexcept {
    static const char* const api_name =
        allocate_flush_instruction_cache(0x1414DB654ll);
    static const char* const module_name = allocate_kernel32_dll(
        reinterpret_cast<const std::byte*>(0x1414DB66Bull));
    HMODULE module = ::GetModuleHandleA(module_name);
    if (module == nullptr) module = ::LoadLibraryA(module_name);
    flush_instruction_cache = module == nullptr ? nullptr :
        reinterpret_cast<decltype(flush_instruction_cache)>(
            ::GetProcAddress(module, api_name));
}



void bind_get_tick_count() noexcept {
    static const char* const api_name =
        allocate_get_tick_count(0x1414DB679ll, 0);
    static const char* const module_name =
        allocate_kernel32_dll_for_get_tick_count(0x1414DB687ll);
    HMODULE module = ::GetModuleHandleA(module_name);
    if (module == nullptr) module = ::LoadLibraryA(module_name);
    get_tick_count = module == nullptr ? nullptr :
        reinterpret_cast<decltype(get_tick_count)>(
            ::GetProcAddress(module, api_name));
}



void bind_get_thread_context() noexcept {
    static const char* const api_name = allocate_get_thread_context_import_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DC725ull));
    static const char* const module_name =
        allocate_kernel32_dll_for_get_thread_context(0x1414DC737ll, 0);
    HMODULE module = ::GetModuleHandleA(module_name);
    if (module == nullptr) module = ::LoadLibraryA(module_name);
    get_thread_context = module == nullptr ? nullptr :
        reinterpret_cast<decltype(get_thread_context)>(
            ::GetProcAddress(module, api_name));
}



void bind_check_remote_debugger_present() noexcept {
    static const char* const api_name =
        allocate_check_remote_debugger_present(0x1414DC745ll);
    static const char* const module_name =
        allocate_kernel32_dll_for_check_remote_debugger_present(
            0x1414DC761ll);
    HMODULE module = ::GetModuleHandleA(module_name);
    if (module == nullptr) module = ::LoadLibraryA(module_name);
    check_remote_debugger_present = module == nullptr ? nullptr :
        reinterpret_cast<decltype(check_remote_debugger_present)>(
            ::GetProcAddress(module, api_name));
}



void bind_query_full_process_image_name() noexcept {
    static const char* const api_name =
        allocate_query_full_process_image_name_w(0x1414DC76Fll);
    static const char* const module_name =
        allocate_kernel32_dll_for_query_full_process_image_name_w(
            0x1414DC78Bll);
    HMODULE module = ::GetModuleHandleA(module_name);
    if (module == nullptr) module = ::LoadLibraryA(module_name);
    query_full_process_image_name = module == nullptr ? nullptr :
        reinterpret_cast<decltype(query_full_process_image_name)>(
            ::GetProcAddress(module, api_name));
}

}
