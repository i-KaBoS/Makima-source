#include "platform/windows/windows.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
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

namespace makima::platform::windows {

extern "C" NTSTATUS NTAPI NtTerminateJobObject(HANDLE job, NTSTATUS status);
extern "C" NTSTATUS NTAPI NtSetInformationJobObject(
    HANDLE job,
    JOBOBJECTINFOCLASS information_class,
    void* information,
    ULONG information_size);
extern "C" BOOLEAN NTAPI RtlCreateUnicodeString(UNICODE_STRING* destination, PCWSTR source);
extern "C" void NTAPI RtlFreeUnicodeString(UNICODE_STRING* value);

struct JobTerminationContext final {
    std::array<std::byte, 0x1098> preserved_state{};
    HANDLE* job_handle{};
};

struct PlatformApiBindings final {
    HMODULE ntdll{};
    HMODULE kernel32{};
    HMODULE advapi32{};
    HMODULE ole32{};
    HMODULE oleaut32{};
    HMODULE gdi32{};
    HMODULE dwmapi{};
    HMODULE dxgi{};
    HMODULE d3d11{};
    HMODULE user32{};
    HMODULE setupapi{};
    HMODULE hid{};
    FARPROC nt_set_information_job_object{};
    FARPROC nt_terminate_job_object{};
    FARPROC nt_set_information_file{};
    FARPROC nt_open_file{};
    FARPROC nt_set_information_thread{};
    FARPROC nt_get_context_thread{};
    FARPROC rtl_image_nt_header{};
    FARPROC rtl_create_unicode_string{};
    FARPROC rtl_free_unicode_string{};
    FARPROC co_initialize_ex{};
    FARPROC co_create_instance{};
    FARPROC co_set_proxy_blanket{};
    FARPROC co_uninitialize{};
    FARPROC sys_alloc_string{};
    FARPROC sys_free_string{};
    FARPROC variant_clear{};
    FARPROC dwm_is_composition_enabled{};
    FARPROC dwm_get_composition_timing_info{};
    FARPROC d3dkmt_open_adapter_from_luid{};
    FARPROC d3dkmt_query_adapter_info{};
    FARPROC d3dkmt_close_adapter{};
    FARPROC create_dxgi_factory1{};
    FARPROC global_memory_status_ex{};
    FARPROC get_system_time{};
    FARPROC get_system_time_as_file_time{};
    FARPROC get_process_id{};
    FARPROC get_file_attributes_w{};
    FARPROC create_directory_w{};
    FARPROC find_first_file_w{};
    FARPROC find_close{};
    FARPROC get_module_handle_a{};
    FARPROC reg_open_key_ex_a{};
    FARPROC reg_query_value_ex_a{};
    FARPROC reg_enum_key_ex_a{};
    FARPROC d3d11_create_device{};
    FARPROC enum_display_devices_a{};
    FARPROC setup_di_get_class_devs_a{};
    FARPROC setup_di_enum_device_info{};
    FARPROC setup_di_open_dev_reg_key{};
    FARPROC setup_di_destroy_device_info_list{};
    FARPROC setup_di_enum_device_interfaces{};
    FARPROC setup_di_get_device_interface_detail_a{};
    FARPROC create_file_a{};
    FARPROC hid_get_attributes{};
    FARPROC hid_get_preparsed_data{};
    FARPROC hid_get_caps{};
    FARPROC hid_get_product_string{};
    FARPROC raise_fail_fast_exception{};
    FARPROC rtl_disown_module_heap_allocation{};
    FARPROC rtl_free_heap{};
    FARPROC module_heap_release{};

    [[nodiscard]] bool complete() const noexcept {
        return ntdll != nullptr && kernel32 != nullptr && advapi32 != nullptr &&
            ole32 != nullptr && oleaut32 != nullptr && gdi32 != nullptr && dwmapi != nullptr && dxgi != nullptr &&
            d3d11 != nullptr && user32 != nullptr && setupapi != nullptr && hid != nullptr &&
            nt_set_information_job_object != nullptr && nt_terminate_job_object != nullptr &&
            nt_set_information_file != nullptr && nt_open_file != nullptr && rtl_image_nt_header != nullptr &&
            nt_set_information_thread != nullptr && nt_get_context_thread != nullptr &&
            rtl_create_unicode_string != nullptr && rtl_free_unicode_string != nullptr &&
            co_initialize_ex != nullptr && co_create_instance != nullptr && co_set_proxy_blanket != nullptr &&
            co_uninitialize != nullptr && sys_alloc_string != nullptr && sys_free_string != nullptr &&
            variant_clear != nullptr && dwm_is_composition_enabled != nullptr &&
            dwm_get_composition_timing_info != nullptr && d3dkmt_open_adapter_from_luid != nullptr &&
            d3dkmt_query_adapter_info != nullptr && d3dkmt_close_adapter != nullptr &&
            create_dxgi_factory1 != nullptr && global_memory_status_ex != nullptr &&
            get_system_time != nullptr && get_system_time_as_file_time != nullptr && get_process_id != nullptr &&
            get_file_attributes_w != nullptr &&
            create_directory_w != nullptr && find_first_file_w != nullptr && find_close != nullptr &&
            get_module_handle_a != nullptr && reg_open_key_ex_a != nullptr && reg_query_value_ex_a != nullptr &&
            reg_enum_key_ex_a != nullptr && d3d11_create_device != nullptr && enum_display_devices_a != nullptr &&
            setup_di_get_class_devs_a != nullptr && setup_di_enum_device_info != nullptr &&
            setup_di_open_dev_reg_key != nullptr && setup_di_destroy_device_info_list != nullptr &&
            setup_di_enum_device_interfaces != nullptr && setup_di_get_device_interface_detail_a != nullptr &&
            create_file_a != nullptr && hid_get_attributes != nullptr && hid_get_preparsed_data != nullptr &&
            hid_get_caps != nullptr && hid_get_product_string != nullptr &&
            raise_fail_fast_exception != nullptr;
    }
};

bool initialize_platform_api_bindings() noexcept {
    static PlatformApiBindings bindings;
    if (bindings.complete()) return true;
    bindings.ntdll = load_dynamic_library("ntdll.dll");
    if (bindings.ntdll == nullptr) bindings.ntdll = LoadLibraryA("ntdll.dll");
    bindings.kernel32 = load_dynamic_library("kernel32.dll");
    if (bindings.kernel32 == nullptr) bindings.kernel32 = LoadLibraryA("kernel32.dll");
    bindings.advapi32 = load_dynamic_library("advapi32.dll");
    bindings.ole32 = load_dynamic_library("ole32.dll");
    bindings.oleaut32 = load_dynamic_library("oleaut32.dll");
    bindings.gdi32 = load_dynamic_library("gdi32.dll");
    bindings.dwmapi = load_dynamic_library("dwmapi.dll");
    bindings.dxgi = load_dynamic_library("dxgi.dll");
    bindings.d3d11 = load_dynamic_library("d3d11.dll");
    bindings.user32 = load_dynamic_library("user32.dll");
    bindings.setupapi = load_dynamic_library("setupapi.dll");
    bindings.hid = load_dynamic_library("hid.dll");

    const auto resolve = [](HMODULE module, const char* name) noexcept {
        FARPROC address = resolve_named_export_from_module(module, name);
        if (address == nullptr && module != nullptr) address = GetProcAddress(module, name);
        return address;
    };
    bindings.nt_set_information_job_object = resolve(bindings.ntdll, "NtSetInformationJobObject");
    bindings.nt_terminate_job_object = resolve(bindings.ntdll, "NtTerminateJobObject");
    bindings.nt_set_information_file = resolve(bindings.ntdll, "NtSetInformationFile");
    bindings.nt_open_file = resolve(bindings.ntdll, "NtOpenFile");
    bindings.nt_set_information_thread = resolve(bindings.ntdll, "NtSetInformationThread");
    bindings.nt_get_context_thread = resolve(bindings.ntdll, "NtGetContextThread");
    bindings.rtl_image_nt_header = resolve(bindings.ntdll, "RtlImageNtHeader");
    bindings.rtl_create_unicode_string = resolve(bindings.ntdll, "RtlCreateUnicodeString");
    bindings.rtl_free_unicode_string = resolve(bindings.ntdll, "RtlFreeUnicodeString");
    bindings.co_initialize_ex = resolve(bindings.ole32, "CoInitializeEx");
    bindings.co_create_instance = resolve(bindings.ole32, "CoCreateInstance");
    bindings.co_set_proxy_blanket = resolve(bindings.ole32, "CoSetProxyBlanket");
    bindings.co_uninitialize = resolve(bindings.ole32, "CoUninitialize");
    bindings.sys_alloc_string = resolve(bindings.oleaut32, "SysAllocString");
    bindings.sys_free_string = resolve(bindings.oleaut32, "SysFreeString");
    bindings.variant_clear = resolve(bindings.oleaut32, "VariantClear");
    bindings.dwm_is_composition_enabled = resolve(bindings.dwmapi, "DwmIsCompositionEnabled");
    bindings.dwm_get_composition_timing_info = resolve(bindings.dwmapi, "DwmGetCompositionTimingInfo");
    bindings.d3dkmt_open_adapter_from_luid = resolve(bindings.gdi32, "D3DKMTOpenAdapterFromLuid");
    bindings.d3dkmt_query_adapter_info = resolve(bindings.gdi32, "D3DKMTQueryAdapterInfo");
    bindings.d3dkmt_close_adapter = resolve(bindings.gdi32, "D3DKMTCloseAdapter");
    bindings.create_dxgi_factory1 = resolve(bindings.dxgi, "CreateDXGIFactory1");
    bindings.global_memory_status_ex = resolve(bindings.kernel32, "GlobalMemoryStatusEx");
    bindings.get_system_time = resolve(bindings.kernel32, "GetSystemTime");
    bindings.get_system_time_as_file_time = resolve(bindings.kernel32, "GetSystemTimeAsFileTime");
    bindings.get_process_id = resolve(bindings.kernel32, "GetProcessId");
    bindings.get_file_attributes_w = resolve(bindings.kernel32, "GetFileAttributesW");
    bindings.create_directory_w = resolve(bindings.kernel32, "CreateDirectoryW");
    bindings.find_first_file_w = resolve(bindings.kernel32, "FindFirstFileW");
    bindings.find_close = resolve(bindings.kernel32, "FindClose");
    bindings.get_module_handle_a = resolve(bindings.kernel32, "GetModuleHandleA");
    bindings.reg_open_key_ex_a = resolve(bindings.advapi32, "RegOpenKeyExA");
    bindings.reg_query_value_ex_a = resolve(bindings.advapi32, "RegQueryValueExA");
    bindings.reg_enum_key_ex_a = resolve(bindings.advapi32, "RegEnumKeyExA");
    bindings.d3d11_create_device = resolve(bindings.d3d11, "D3D11CreateDevice");
    bindings.enum_display_devices_a = resolve(bindings.user32, "EnumDisplayDevicesA");
    bindings.setup_di_get_class_devs_a = resolve(bindings.setupapi, "SetupDiGetClassDevsA");
    bindings.setup_di_enum_device_info = resolve(bindings.setupapi, "SetupDiEnumDeviceInfo");
    bindings.setup_di_open_dev_reg_key = resolve(bindings.setupapi, "SetupDiOpenDevRegKey");
    bindings.setup_di_destroy_device_info_list = resolve(bindings.setupapi, "SetupDiDestroyDeviceInfoList");
    bindings.setup_di_enum_device_interfaces = resolve(bindings.setupapi, "SetupDiEnumDeviceInterfaces");
    bindings.setup_di_get_device_interface_detail_a = resolve(bindings.setupapi, "SetupDiGetDeviceInterfaceDetailA");
    bindings.create_file_a = resolve(bindings.kernel32, "CreateFileA");
    bindings.hid_get_attributes = resolve(bindings.hid, "HidD_GetAttributes");
    bindings.hid_get_preparsed_data = resolve(bindings.hid, "HidD_GetPreparsedData");
    bindings.hid_get_caps = resolve(bindings.hid, "HidP_GetCaps");
    bindings.hid_get_product_string = resolve(bindings.hid, "HidD_GetProductString");
    bindings.raise_fail_fast_exception = resolve_raise_fail_fast_exception(1U);
    bindings.rtl_disown_module_heap_allocation = resolve_first_module_heap_text_release(
        bindings.ntdll, "RtlDisownModuleHeapAllocation");
    bindings.rtl_free_heap = resolve(bindings.ntdll, "RtlFreeHeap");
    bindings.module_heap_release = resolve_module_heap_release_routine(
        bindings.ntdll, "RtlDisownModuleHeapAllocation");
    const char* module_path = get_current_ansi_module_file_path();
    if (*module_path == '\0') return false;
    constexpr std::array<char, 18> coordination_marker{
        's','e','c','u','r','i','t','y','-','p','l','a','t','f','o','r','m','\0'};
    std::uint32_t marker_section_rva = 0;
    std::uint32_t marker_section_size = 0;
    std::uint32_t marker_section_index = 0;
    std::uintptr_t marker_image_base = 0;
    (void)find_pattern_in_loaded_image_sections(
        &bindings,
        module_path,
        coordination_marker.data(),
        static_cast<std::uint32_t>(coordination_marker.size() - 1),
        &marker_section_rva,
        &marker_section_size,
        &marker_section_index,
        &marker_image_base);
    return bindings.complete();
}

std::uint64_t terminate_job_and_restore_impersonation(JobTerminationContext* context) noexcept {
    RevertToSelf();
    if (context == nullptr || context->job_handle == nullptr || *context->job_handle == nullptr) return 0;
    const NTSTATUS status = NtTerminateJobObject(*context->job_handle, 0);
    *context->job_handle = nullptr;
    return status >= 0 ? 1U : 0U;
}

bool configure_native_job_information(void*, HANDLE job, const wchar_t* native_name) noexcept {
    if (job == nullptr || native_name == nullptr || *native_name == L'\0') return false;

    UNICODE_STRING name{};
    if (!RtlCreateUnicodeString(&name, native_name)) return false;
    const NTSTATUS status = NtSetInformationJobObject(
        job,
        static_cast<JOBOBJECTINFOCLASS>(0x2d),
        &name,
        static_cast<ULONG>(sizeof(name)));
    RtlFreeUnicodeString(&name);
    return status >= 0;
}

}
