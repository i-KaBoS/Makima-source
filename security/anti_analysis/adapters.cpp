#include "security/anti_analysis/anti_analysis.hpp"
#include "security/environment/environment.hpp"

#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <new>
#include <ranges>
#include <string_view>
#include <utility>
#include <vector>

namespace makima::security::anti_analysis {



char* allocate_get_thread_context_import_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr std::string_view value{"GetThreadContext"};
    auto* output = static_cast<char*>(::operator new(value.size() + 1U));
    std::memcpy(output, value.data(), value.size());
    output[value.size()] = '\0';
    return output;
}

namespace {

using GetLastErrorFunction = decltype(&::GetLastError);

GetLastErrorFunction get_last_error_binding = nullptr;





int register_get_last_error_binding() noexcept {
    HMODULE const module = LoadLibraryA("kernel32.dll");
    if (module != nullptr) {
        get_last_error_binding = reinterpret_cast<GetLastErrorFunction>(
            GetProcAddress(module, "GetLastError"));
    }
    return 0;
}

[[maybe_unused]] const int get_last_error_registration =
    register_get_last_error_binding();



wchar_t* allocate_ida_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t executable_name[] = L"ida.exe";
    static_assert(sizeof(executable_name) == 16U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(executable_name)));
    std::memcpy(output, executable_name, sizeof(executable_name));
    return output;
}



wchar_t* allocate_binary_ninja_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t executable_name[] = L"binaryninja";
    static_assert(sizeof(executable_name) == 24U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(executable_name)));
    std::memcpy(output, executable_name, sizeof(executable_name));
    return output;
}
}




void append_probe_scalar(std::vector<std::byte>& bytes, std::byte value) {
    bytes.push_back(value);
}


void append_low_order_probe_scalar(
    std::vector<std::byte>& bytes,
    std::uint32_t value) {
    bytes.push_back(static_cast<std::byte>(value & 0xffU));
}


void append_probe_integer_little_endian(
    std::vector<std::byte>& bytes,
    std::uint32_t value) {
    for (unsigned shift = 0; shift != 32; shift += 8) {
        bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}


void append_probe_address_little_endian(
    std::vector<std::byte>& bytes,
    std::uint64_t value) {
    for (unsigned shift = 0; shift != 64; shift += 8) {
        bytes.push_back(static_cast<std::byte>((value >> shift) & 0xffU));
    }
}




void emit_native_debug_probe(
    std::uintptr_t reserved_context,
    std::vector<std::byte>& bytes,
    std::uintptr_t probe_target) {
    (void)reserved_context;
    constexpr std::array prefix{
        std::byte{0x55}, std::byte{0x48}, std::byte{0x89}, std::byte{0xe5},
        std::byte{0x48}, std::byte{0xb8}};
    bytes.insert(bytes.end(), prefix.begin(), prefix.end());
    append_probe_address_little_endian(
        bytes, static_cast<std::uint64_t>(probe_target));
    constexpr std::array suffix{
        std::byte{0x4c}, std::byte{0x31}, std::byte{0xc0},
        std::byte{0x49}, std::byte{0x33}, std::byte{0xc0},
        std::byte{0x4d}, std::byte{0x31}, std::byte{0xc9},
        std::byte{0x4c}, std::byte{0x39}, std::byte{0xca},
        std::byte{0x7d}, std::byte{0x0d},
        std::byte{0x42}, std::byte{0x30}, std::byte{0x04}, std::byte{0x09},
        std::byte{0x48}, std::byte{0xc1}, std::byte{0xc8}, std::byte{0x08},
        std::byte{0x49}, std::byte{0xff}, std::byte{0xc1},
        std::byte{0xeb}, std::byte{0xee},
        std::byte{0x5d}, std::byte{0xc3}};
    bytes.insert(bytes.end(), suffix.begin(), suffix.end());
}



[[nodiscard]] bool early_nt_global_flag_debug_bits_are_clear() noexcept {
#if defined(_M_X64)
    const auto* peb = reinterpret_cast<const std::byte*>(__readgsqword(0x60));
    std::uint32_t flags{};
    std::memcpy(&flags, peb + 0xbc, sizeof(flags));
    return (flags & 0x70U) == 0;
#else
    return true;
#endif
}



[[nodiscard]] bool peb_being_debugged_is_clear() noexcept {
#if defined(_M_X64)
    const auto* peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
    return peb[2] == 0;
#else
    return IsDebuggerPresent() == FALSE;
#endif
}




[[nodiscard]] bool nt_global_flag_debug_bits_are_clear() noexcept {
#if defined(_M_X64)
    const auto* peb = reinterpret_cast<const std::byte*>(__readgsqword(0x60));
    if (peb == nullptr) return true;
    std::uint32_t flags{};
    std::memcpy(&flags, peb + 0xbc, sizeof(flags));
    return (flags & 0x70U) == 0;
#else
    return true;
#endif
}



[[nodiscard]] bool process_heap_debug_flags_are_clear() noexcept {
#if defined(_M_X64)
    const auto* peb = reinterpret_cast<const std::byte*>(__readgsqword(0x60));
    if (peb == nullptr) return true;
    std::uintptr_t process_heap{};
    std::memcpy(&process_heap, peb + 0x30, sizeof(process_heap));
    if (process_heap == 0) return true;
    unsigned char flags{};
    std::uint32_t force_flags{};
    std::memcpy(&flags, reinterpret_cast<const void*>(process_heap + 0x70), sizeof(flags));
    std::memcpy(
        &force_flags,
        reinterpret_cast<const void*>(process_heap + 0x74),
        sizeof(force_flags));
    return (flags & 0x60U) == 0 && force_flags == 0;
#else
    return true;
#endif
}




wchar_t* allocate_userinit_executable_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"userinit.exe";
    static_assert(sizeof(value) == 26U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}





wchar_t* allocate_conhost_executable_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"conhost.exe";
    static_assert(sizeof(value) == 0x18);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}








const wchar_t* terminal_host_image_name() {
    static const wchar_t* value = allocate_conhost_executable_name(
        reinterpret_cast<const std::uint16_t*>(0x1414DB81Eull));
    return value;
}


const wchar_t* x32dbg_process_token() noexcept {
    static const wchar_t* value = allocate_x32dbg(
        reinterpret_cast<const std::uint16_t*>(0x1414DBA94ull));
    return value;
}


const wchar_t* ollydbg_process_token() noexcept {
    static const wchar_t* value = allocate_ollydbg(
        reinterpret_cast<const std::uint16_t*>(0x1414DBAA4ull));
    return value;
}


const wchar_t* windbg_process_token() noexcept {
    static const wchar_t* value = allocate_windbg(
        reinterpret_cast<const std::uint16_t*>(0x1414DBAB6ull));
    return value;
}


const wchar_t* dbgsrv_process_token() noexcept {
    static const wchar_t* value = allocate_dbgsrv(
        reinterpret_cast<const std::uint16_t*>(0x1414DBAC6ull));
    return value;
}


const wchar_t* immunity_debugger_process_token() noexcept {
    static const wchar_t* value = allocate_immunitydebugger(0x1414DBAD6ll, 0);
    return value;
}


const wchar_t* ida_process_token() noexcept {
    static const wchar_t* value = allocate_ida_token(
        reinterpret_cast<const std::uint16_t*>(0x1414DBAFAull));
    return value;
}


const wchar_t* ida64_process_token() noexcept {
    static const wchar_t* value = allocate_ida64_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB0Cull));
    return value;
}


const wchar_t* ghidra_process_token() noexcept {
    static const wchar_t* value = allocate_ghidra(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB22ull));
    return value;
}


const wchar_t* binary_ninja_process_token() noexcept {
    static const wchar_t* value = allocate_binary_ninja_token(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB32ull));
    return value;
}


const wchar_t* radare2_process_token() noexcept {
    static const wchar_t* value = allocate_radare2(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB4Cull));
    return value;
}


const wchar_t* iaito_process_token() noexcept {
    static const wchar_t* value = allocate_iaito(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB5Eull));
    return value;
}


const wchar_t* dnspy_process_token() noexcept {
    static const wchar_t* value = allocate_dnspy(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB6Cull));
    return value;
}


const wchar_t* dotpeek_process_token() noexcept {
    static const wchar_t* value = allocate_dotpeek(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB7Aull));
    return value;
}


const wchar_t* ilspy_process_token() noexcept {
    static const wchar_t* value = allocate_ilspy(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB8Cull));
    return value;
}


const wchar_t* de4dot_process_token() noexcept {
    static const wchar_t* value = allocate_de4dot(
        reinterpret_cast<const std::uint16_t*>(0x1414DBB9Aull));
    return value;
}


const wchar_t* pe_bear_process_token() noexcept {
    static const wchar_t* value = allocate_pe_bear(
        reinterpret_cast<const std::uint16_t*>(0x1414DBBAAull));
    return value;
}


const wchar_t* cff_explorer_process_token() noexcept {
    static const wchar_t* value = allocate_cffexplorer(0x1414DBBBCll, 0);
    return value;
}


const wchar_t* pe_studio_process_token() noexcept {
    static const wchar_t* value = allocate_pestudio(
        reinterpret_cast<const std::uint16_t*>(0x1414DBBD6ull));
    return value;
}


const wchar_t* editor_010_process_token() noexcept {
    static const wchar_t* value = allocate_010editor(
        reinterpret_cast<const std::uint16_t*>(0x1414DBBEAull));
    return value;
}


const wchar_t* process_hacker_process_token() noexcept {
    static const wchar_t* value = allocate_processhacker(
        reinterpret_cast<const std::uint16_t*>(0x1414DBC00ull));
    return value;
}


const wchar_t* system_informer_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_system_informer_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC1Eull));
    return value;
}


const wchar_t* b_sentinel_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_b_sentinel_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC3Eull));
    return value;
}


const wchar_t* process_explorer_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_process_explorer_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC50ull));
    return value;
}


const wchar_t* reclass_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_reclass_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC62ull));
    return value;
}


const wchar_t* scylla_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_scylla_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC74ull));
    return value;
}


const wchar_t* fiddler_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_fiddler_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC84ull));
    return value;
}


const wchar_t* http_toolkit_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_http_toolkit_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBC96ull));
    return value;
}


const wchar_t* proxyman_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_proxyman_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBCB0ull));
    return value;
}


const wchar_t* reqable_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_reqable_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBCC4ull));
    return value;
}


const wchar_t* http_analyzer_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_http_analyzer_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBCD6ull));
    return value;
}


const wchar_t* http_debugger_pro_process_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_http_debugger_pro_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBCF2ull));
    return value;
}


const wchar_t* http_debugger_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_http_debugger_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD14ull));
    return value;
}


const wchar_t* bracket_sentinel_process_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_bracket_sentinel_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD30ull));
    return value;
}


const wchar_t* charles_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_charles_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD46ull));
    return value;
}


const wchar_t* burp_suite_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_burp_suite_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD58ull));
    return value;
}


const wchar_t* echo_mirage_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_echo_mirage_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD6Eull));
    return value;
}


const wchar_t* wireshark_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_wireshark_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD86ull));
    return value;
}


const wchar_t* tshark_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_tshark_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBD9Cull));
    return value;
}


const wchar_t* dumpcap_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_dumpcap_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBDACull));
    return value;
}


const wchar_t* rawcap_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_rawcap_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBDBEull));
    return value;
}


const wchar_t* smsniff_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_smsniff_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBDCEull));
    return value;
}


const wchar_t* network_miner_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_network_miner_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBDE0ull));
    return value;
}


const wchar_t* windump_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_windump_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBDFCull));
    return value;
}


const wchar_t* equals_sentinel_process_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_equals_sentinel_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE0Eull));
    return value;
}


const wchar_t* api_monitor_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_api_monitor_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE20ull));
    return value;
}


const wchar_t* rohitab_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_rohitab_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE38ull));
    return value;
}


const wchar_t* winapi_override_process_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_winapi_override_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE4Aull));
    return value;
}


const wchar_t* spy_studio_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_spy_studio_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE6Aull));
    return value;
}


const wchar_t* wpe_pro_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_wpe_pro_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE80ull));
    return value;
}


const wchar_t* xenos_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_xenos_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBE92ull));
    return value;
}


const wchar_t* extreme_injector_process_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_extreme_injector_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBEA0ull));
    return value;
}


const wchar_t* gh_injector_process_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_gh_injector_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBEC4ull));
    return value;
}


const wchar_t* http_debugger_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_http_debugger_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBF40ull));
    return value;
}


const wchar_t* winapi_override_module_token() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_winapi_override_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBF5Cull));
    return value;
}


const wchar_t* spy_studio_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_spy_studio_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBF7Cull));
    return value;
}


const wchar_t* echo_mirage_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_echo_mirage_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBF92ull));
    return value;
}


const wchar_t* fiddler_core_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_fiddler_core_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBFAAull));
    return value;
}


const wchar_t* titanium_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_titanium_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBFC4ull));
    return value;
}


const wchar_t* http_toolkit_module_token() noexcept {
    static const wchar_t* value =
        makima::security::environment::allocate_http_toolkit_module_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBFD8ull));
    return value;
}


const char* hardware_breakpoint_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_hardware_breakpoint_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC1C9ull));
    return value;
}


const char* hardware_breakpoint_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_hardware_breakpoint_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC1E2ull));
    return value;
}


const char* hardware_breakpoint_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_hardware_breakpoint_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC1E6ull));
    return value;
}


const char* nt_global_flag_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_nt_global_flag_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC206ull));
    return value;
}


const char* nt_global_flag_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_nt_global_flag_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC234ull));
    return value;
}


const char* nt_global_flag_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_nt_global_flag_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC238ull));
    return value;
}


const char* tooling_process_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_tooling_process_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC253ull));
    return value;
}


const char* tooling_process_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_tooling_process_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC27Cull));
    return value;
}


const char* tooling_process_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_tooling_process_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC280ull));
    return value;
}


const wchar_t* ssl_key_log_environment_name() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_ssl_key_log_environment_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DC29Cull));
    return value;
}


const wchar_t* ssl_key_log_environment_name_for_clear() noexcept {
    static const wchar_t* value = makima::security::environment::
        allocate_ssl_key_log_environment_name_for_clear(
            reinterpret_cast<const std::uint16_t*>(0x1414DC2BAull));
    return value;
}


const char* ssl_key_log_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_ssl_key_log_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC2D8ull));
    return value;
}


const char* ssl_key_log_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_ssl_key_log_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC2F7ull));
    return value;
}


const char* ssl_key_log_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_ssl_key_log_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC2FBull));
    return value;
}


const char* suspicious_module_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_suspicious_module_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC315ull));
    return value;
}


const char* suspicious_module_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_suspicious_module_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC33Bull));
    return value;
}


const char* suspicious_module_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_suspicious_module_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC33Full));
    return value;
}


const char* invalid_handle_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_invalid_handle_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC35Dull));
    return value;
}


const char* invalid_handle_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_invalid_handle_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC390ull));
    return value;
}


const char* invalid_handle_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_invalid_handle_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC394ull));
    return value;
}


const char* heap_flags_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_heap_flags_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC3B7ull));
    return value;
}


const char* heap_flags_format() noexcept {
    static const char* value = makima::security::environment::
        allocate_percent_s_heap_flags_format(
            reinterpret_cast<const std::uint8_t*>(0x1414DC3E0ull));
    return value;
}


const char* heap_flags_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_heap_flags_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC3E4ull));
    return value;
}


const char* remote_debugger_verbose_detail() noexcept {
    static const char* value = makima::security::environment::
        allocate_remote_debugger_verbose_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC591ull));
    return value;
}


const char* remote_debugger_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_remote_debugger_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC5C7ull));
    return value;
}


const char* invalid_handle_verbose_detail() noexcept {
    static const char* value = makima::security::environment::
        allocate_invalid_handle_verbose_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC5E3ull));
    return value;
}


const char* invalid_handle_verbose_event() noexcept {
    static const char* value = makima::security::environment::
        allocate_invalid_handle_verbose_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC625ull));
    return value;
}


const char* heap_flags_verbose_detail() noexcept {
    static const char* value = makima::security::environment::
        allocate_heap_flags_verbose_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC648ull));
    return value;
}


const char* heap_flags_verbose_event() noexcept {
    static const char* value = makima::security::environment::
        allocate_heap_flags_verbose_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC67Cull));
    return value;
}


const char* timing_anomaly_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_timing_anomaly_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC693ull));
    return value;
}


const char* timing_anomaly_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_timing_anomaly_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC6B8ull));
    return value;
}


const char* bad_parent_process_detail() noexcept {
    static const char* value =
        makima::security::environment::allocate_bad_parent_process_detail(
            reinterpret_cast<const std::uint8_t*>(0x1414DC6D3ull));
    return value;
}


const char* bad_parent_process_event() noexcept {
    static const char* value =
        makima::security::environment::allocate_bad_parent_process_event(
            reinterpret_cast<const std::uint8_t*>(0x1414DC706ull));
    return value;
}





const wchar_t* powershell_image_name() noexcept {
    static const wchar_t* value = allocate_powershell_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB7C0ull));
    return value;
}


const wchar_t* pwsh_image_name() noexcept {
    static const wchar_t* value = allocate_pwsh_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB7E0ull));
    return value;
}


const wchar_t* windows_terminal_image_name() noexcept {
    static const wchar_t* value = allocate_windows_terminal_exe(0x1414DB7F4ll);
    return value;
}


const wchar_t* wt_image_name() noexcept {
    static const wchar_t* value = allocate_wt_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB838ull));
    return value;
}


const wchar_t* chrome_image_name() noexcept {
    static const wchar_t* value = allocate_chrome_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB848ull));
    return value;
}


const wchar_t* edge_image_name() noexcept {
    static const wchar_t* value = allocate_msedge_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB860ull));
    return value;
}


const wchar_t* firefox_image_name() noexcept {
    static const wchar_t* value = allocate_firefox_exe(0x1414DB878ll);
    return value;
}


const wchar_t* opera_image_name() noexcept {
    static const wchar_t* value = allocate_opera_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB892ull));
    return value;
}


const wchar_t* brave_image_name() noexcept {
    static const wchar_t* value = allocate_brave_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB8A8ull));
    return value;
}


const wchar_t* vivaldi_image_name() noexcept {
    static const wchar_t* value = allocate_vivaldi_exe(0x1414DB8BEll);
    return value;
}


const wchar_t* internet_explorer_image_name() noexcept {
    static const wchar_t* value = allocate_iexplore_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB8D8ull));
    return value;
}


const wchar_t* seven_zip_file_manager_image_name() noexcept {
    static const wchar_t* value = allocate_7z_fm_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB8F4ull));
    return value;
}


const wchar_t* winrar_image_name() noexcept {
    static const wchar_t* value = allocate_winrar_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB908ull));
    return value;
}


const wchar_t* total_commander_image_name() noexcept {
    static const wchar_t* value = allocate_total_commander_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB920ull));
    return value;
}


const wchar_t* discord_image_name() noexcept {
    static const wchar_t* value = allocate_discord_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB94Aull));
    return value;
}


const wchar_t* discord_ptb_image_name() noexcept {
    static const wchar_t* value = allocate_discord_ptb_exe(0x1414DB964ll);
    return value;
}


const wchar_t* discord_canary_image_name() noexcept {
    static const wchar_t* value = allocate_discord_canary_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB984ull));
    return value;
}


const wchar_t* telegram_image_name() noexcept {
    static const wchar_t* value = allocate_telegram_exe(0x1414DB9AAll);
    return value;
}


const wchar_t* rundll32_image_name() noexcept {
    static const wchar_t* value = allocate_rundll32_exe(0x1414DB9C6ll);
    return value;
}


const wchar_t* task_manager_image_name() noexcept {
    static const wchar_t* value = allocate_taskmgr_exe(0x1414DB9E2ll);
    return value;
}


const wchar_t* dll_host_image_name() noexcept {
    static const wchar_t* value = allocate_dllhost_exe(
        reinterpret_cast<const std::uint16_t*>(0x1414DB9FCull));
    return value;
}

}
