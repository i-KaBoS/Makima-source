#include "security/environment/environment.hpp"

#include <cstddef>
#include <cstring>
#include <new>
#include <vector>
#include <windows.h>

namespace makima::security::environment {

namespace {

template <std::size_t Size>
char* allocate_literal_copy(const char (&value)[Size]) {
    auto* output = static_cast<char*>(::operator new(Size));
    std::memcpy(output, value, Size);
    return output;
}

template <std::size_t Size>
wchar_t* allocate_wide_literal_copy(const wchar_t (&value)[Size]) {
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}

}

void release_inventory_scratch(std::vector<std::byte>& scratch) noexcept {
    if (!scratch.empty()) SecureZeroMemory(scratch.data(), scratch.size());
    scratch.clear();
    scratch.shrink_to_fit();
}


wchar_t* allocate_system_informer_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"systeminformer";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_b_sentinel_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"BBBBBBB";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_process_explorer_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"procexp";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_reclass_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"reclass";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_scylla_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"scylla";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_fiddler_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"fiddler";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_toolkit_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httptoolkit";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_proxyman_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"proxyman";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_reqable_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"reqable";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_analyzer_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httpanalyzer";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_debugger_pro_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httpdebuggerpro";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_debugger_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httpdebugger";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_bracket_sentinel_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"]]]]]]]]]";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_charles_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"charles";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_burp_suite_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"burpsuite";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_echo_mirage_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"echomirage";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_wireshark_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"wireshark";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_tshark_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"tshark";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_dumpcap_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"dumpcap";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_rawcap_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"rawcap";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_smsniff_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"smsniff";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_network_miner_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"networkminer";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_windump_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"windump";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_equals_sentinel_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"=======";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_api_monitor_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"apimonitor";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_rohitab_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"rohitab";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_winapi_override_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"winapioverride";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_spy_studio_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"spystudio";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_wpe_pro_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"wpe pro";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_xenos_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"xenos";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_extreme_injector_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"extreme injector";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_gh_injector_process_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"ghinjector";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_debugger_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httpdebugger";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_winapi_override_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"winapioverride";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_spy_studio_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"spystudio";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_echo_mirage_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"echomirage";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_fiddler_core_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"fiddlercore";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_titanium_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"titanium";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_http_toolkit_module_token(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"httptoolkit";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_hardware_breakpoint_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"DR0-DR3 set"})";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_hardware_breakpoint_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_hardware_breakpoint_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.hardware_breakpoint";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_global_flag_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"NtGlobalFlag heap-debug bits set"})";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_nt_global_flag_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_global_flag_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.nt_global_flag";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_tooling_process_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"cheat-tooling process found"})";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_tooling_process_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_tooling_process_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.tooling_process";
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_ssl_key_log_environment_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SSLKEYLOGFILE";
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_ssl_key_log_environment_name_for_clear(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SSLKEYLOGFILE";
    static_assert(sizeof(value) == 28U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_ssl_key_log_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"SSLKEYLOGFILE set"})";
    static_assert(sizeof(value) == 30U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_ssl_key_log_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_ssl_key_log_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.sslkeylogfile";
    static_assert(sizeof(value) == 25U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_suspicious_module_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"cheat-tooling DLL loaded"})";
    static_assert(sizeof(value) == 37U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_suspicious_module_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_suspicious_module_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.suspicious_module";
    static_assert(sizeof(value) == 29U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_invalid_handle_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"CloseHandle(invalid) raised exception"})";
    static_assert(sizeof(value) == 50U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_invalid_handle_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_invalid_handle_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.close_handle_exception";
    static_assert(sizeof(value) == 34U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_heap_flags_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"ProcessHeap debug flags set"})";
    static_assert(sizeof(value) == 40U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_heap_flags_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_heap_flags_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.heap_flags";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_remote_debugger_verbose_detail(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"CheckRemoteDebuggerPresent returned TRUE"})";
    static_assert(sizeof(value) == 53U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_remote_debugger_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.remote_debugger";
    static_assert(sizeof(value) == 27U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_invalid_handle_verbose_detail(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"CloseHandle(invalid) raised EXCEPTION_INVALID_HANDLE"})";
    static_assert(sizeof(value) == 65U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_invalid_handle_verbose_event(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.close_handle_exception";
    static_assert(sizeof(value) == 34U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_heap_flags_verbose_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"ProcessHeap debug flags/ForceFlags set"})";
    static_assert(sizeof(value) == 51U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_heap_flags_verbose_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.heap_flags";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_timing_anomaly_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"trivial loop took >50ms"})";
    static_assert(sizeof(value) == 36U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_timing_anomaly_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.timing_anomaly";
    static_assert(sizeof(value) == 26U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_bad_parent_process_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"parent process not in shell whitelist"})";
    static_assert(sizeof(value) == 50U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_bad_parent_process_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.bad_parent_process";
    static_assert(sizeof(value) == 30U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_module_scan_cheat_engine_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"cheatengine";
    static_assert(sizeof(value) == 24U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_module_scan_speedhack_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"speedhack";
    static_assert(sizeof(value) == 20U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_module_scan_dbk64_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"dbk64";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_module_scan_dbk32_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"dbk32";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_module_scan_api_monitor_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"apimonitor";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_query_information_process_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtQueryInformationProcess";
    static_assert(sizeof(value) == 26U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_set_information_thread_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtSetInformationThread";
    static_assert(sizeof(value) == 23U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_close_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtClose";
    static_assert(sizeof(value) == 8U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_nt_get_context_thread_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "NtGetContextThread";
    static_assert(sizeof(value) == 19U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_peb_debug_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_peb_being_debugged_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.peb_being_debugged";
    static_assert(sizeof(value) == 30U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_port_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"ProcessDebugPort != 0"})";
    static_assert(sizeof(value) == 34U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_process_debug_port_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_port_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.debug_port";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_flags_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"ProcessDebugFlags == 0"})";
    static_assert(sizeof(value) == 35U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_process_debug_flags_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_object_detail(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"ProcessDebugObjectHandle non-NULL"})";
    static_assert(sizeof(value) == 46U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_process_debug_object_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_process_debug_object_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_debug.process_debug_object";
    static_assert(sizeof(value) == 32U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_remote_debugger_present_detail(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = R"({"check":"CheckRemoteDebuggerPresent TRUE"})";
    static_assert(sizeof(value) == 44U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_percent_s_remote_debugger_present_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "%s";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_get_process_id_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "GetProcessId";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}



char* allocate_kernel32_for_get_process_id(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("kernel32.dll");
}


char* allocate_unauthorized_mapping_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"unauthorized_map","caller":"0x%llX","protect":"0x%lX"})";
    static_assert(sizeof(value) == 65U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_blocked_mapping_event_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("anti_inject.blocked_map");
}


char* allocate_text_section_crc_mismatch_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(
        "{\"check\":\"text_section_crc_mismatch\","
        "\"text_size\":%zu,\"baseline_crc\":%u}");
}


char* allocate_remote_thread_detail_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"remote_thread","caller":"0x%llX","start":"0x%llX"})";
    static_assert(sizeof(value) == 61U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_remote_thread_blocked_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_inject.blocked_thread";
    static_assert(sizeof(value) == 27U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_rwx_thread_start_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"rwx_thread_start","caller":"0x%llX","start":"0x%llX"})";
    static_assert(sizeof(value) == 64U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_rwx_thread_start_blocked_event(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_inject.blocked_thread";
    static_assert(sizeof(value) == 27U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_rwx_text_protection_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"rwx_on_text","caller":"0x%llX","target":"0x%llX","protect":"0x%lX"})";
    static_assert(sizeof(value) == 78U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_blocked_protect_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_inject.blocked_protect";
    static_assert(sizeof(value) == 28U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_external_suspend_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"external_suspend","caller":"0x%llX"})";
    static_assert(sizeof(value) == 47U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_blocked_suspend_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_inject.blocked_suspend";
    static_assert(sizeof(value) == 28U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_thread_suspend_detail_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] =
        R"({"check":"thread_suspend","caller":"0x%llX","tid":%llu})";
    static_assert(sizeof(value) == 56U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_suspect_suspend_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_inject.suspect_suspend";
    static_assert(sizeof(value) == 28U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_text_crc_mismatch_event(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "anti_tamper.text_crc_mismatch";
    static_assert(sizeof(value) == 30U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_virtualbox_hypervisor_signature(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "VBoxVBox";
    static_assert(sizeof(value) == 9U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_parallels_hypervisor_signature(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "prl ";
    static_assert(sizeof(value) == 5U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_bhyve_hypervisor_signature(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "bhyve";
    static_assert(sizeof(value) == 6U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_reg_open_key_ex_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "RegOpenKeyExA";
    static_assert(sizeof(value) == 14U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_advapi32_for_reg_open_key_ex_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "advapi32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_advapi32_for_reg_close_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "advapi32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_reg_query_value_ex_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "RegQueryValueExA";
    static_assert(sizeof(value) == 17U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_advapi32_for_reg_query_value_ex_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "advapi32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_qemu_hypervisor_signature(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "QEMU";
    static_assert(sizeof(value) == 5U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_global_memory_status_ex_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "GlobalMemoryStatusEx";
    static_assert(sizeof(value) == 21U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_kernel32_for_global_memory_status_ex(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "kernel32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_content_app_ex_cache_path_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] =
        L"%s\\Microsoft\\Windows\\INetCache\\Content.AppEx";
    static_assert(sizeof(value) == 90U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_internet_cache_path_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%s\\Microsoft\\Windows\\INetCache";
    static_assert(sizeof(value) == 62U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_create_directory_w_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "CreateDirectoryW";
    static_assert(sizeof(value) == 17U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_kernel32_for_create_directory_w(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "kernel32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_cache_record_filename_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%02x%02x%02x%02x%02x%02x%02x%02x.dat";
    static_assert(sizeof(value) == 74U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_cache_record_search_pattern(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%s\\*.dat";
    static_assert(sizeof(value) == 18U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_find_first_file_w_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "FindFirstFileW";
    static_assert(sizeof(value) == 15U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_kernel32_for_find_first_file_w(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "kernel32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_cache_record_child_path_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%s\\%s";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_kernel32_for_find_next_file_w(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "kernel32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_find_close_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "FindClose";
    static_assert(sizeof(value) == 10U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_kernel32_for_find_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "kernel32.dll";
    static_assert(sizeof(value) == 13U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_cache_record_search_pattern_for_reader(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%s\\*.dat";
    static_assert(sizeof(value) == 18U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_cache_record_child_path_format_for_reader(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"%s\\%s";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_quote_escape(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\\"";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_backslash_escape(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\\\";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_newline_escape(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\n";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_carriage_return_escape(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\r";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_tab_escape(const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\t";
    static_assert(sizeof(value) == 3U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_unicode_escape_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    constexpr char value[] = "\\u%04x";
    static_assert(sizeof(value) == 7U);
    auto* output = static_cast<char*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_property_comma_for_string(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_json_property_colon_for_string(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\":");
}


char* allocate_json_property_comma_for_integer(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_signed_integer_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%lld");
}


char* allocate_json_property_colon_for_integer(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\":");
}


char* allocate_x86_64_sse2_architecture_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 SSE2");
}


char* allocate_json_property_comma_for_boolean(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_json_property_colon_for_boolean(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\":");
}


char* allocate_json_true_literal(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("true");
}


char* allocate_json_false_literal(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("false");
}


char* allocate_hard_disk_classification_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HDD");
}


char* allocate_get_system_time_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("GetSystemTime");
}


char* allocate_kernel32_for_get_system_time(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("kernel32.dll");
}


char* allocate_co_initialize_ex_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CoInitializeEx");
}


char* allocate_ole32_for_co_initialize_ex(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ole32.dll");
}


char* allocate_co_initialize_security_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CoInitializeSecurity");
}


char* allocate_ole32_for_co_initialize_security(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ole32.dll");
}


char* allocate_co_create_instance_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CoCreateInstance");
}


char* allocate_ole32_for_co_create_instance(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ole32.dll");
}


char* allocate_co_set_proxy_blanket_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CoSetProxyBlanket");
}


char* allocate_ole32_for_co_set_proxy_blanket(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ole32.dll");
}


char* allocate_create_dxgi_factory1_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CreateDXGIFactory1");
}


char* allocate_dxgi_for_create_dxgi_factory1(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("dxgi.dll");
}


char* allocate_co_uninitialize_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CoUninitialize");
}


char* allocate_ole32_for_co_uninitialize(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ole32.dll");
}


char* allocate_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_json_schema_one_fragment(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"schema\":1");
}


char* allocate_iso_8601_utc_timestamp_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%04u-%02u-%02uT%02u:%02u:%02uZ");
}


wchar_t* allocate_edge_update_credentials_path_format(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(
        L"%s\\Microsoft\\EdgeUpdate\\creds_v2.dat");
}


char* allocate_collected_at_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"collected_at\":");
}


wchar_t* allocate_wmi_root_cimv2_namespace(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"ROOT\\CIMV2";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_os_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"os\":{");
}


char* allocate_get_module_handle_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("GetModuleHandleA");
}


char* allocate_kernel32_for_get_module_handle_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("kernel32.dll");
}


char* allocate_ntdll_module_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ntdll.dll");
}


char* allocate_rtl_get_version_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("RtlGetVersion");
}


char* allocate_windows_family_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Windows");
}


char* allocate_windows_11_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Windows 11");
}


char* allocate_windows_10_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Windows 10");
}


char* allocate_os_name_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("name");
}


char* allocate_os_build_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("build");
}


char* allocate_os_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_cpu_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"cpu\":{");
}


char* allocate_unknown_os_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_cpu_registry_key_path(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0");
}


char* allocate_cpu_frequency_value_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("~MHz");
}




char* allocate_processor_name_value_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ProcessorNameString");
}


char* allocate_base_mhz_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("base_mhz");
}


char* allocate_cpu_name_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("name");
}


char* allocate_logical_processors_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("logical_processors");
}


char* allocate_x86_sse2_or_lower_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86 (SSE2 or lower)");
}


char* allocate_x86_64_avx512_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 AVX-512");
}


char* allocate_x86_64_avx2_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 AVX2");
}


char* allocate_x86_64_avx_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 AVX");
}


char* allocate_x86_64_sse42_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 SSE4.2");
}


char* allocate_x86_64_sse41_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("x86-64 SSE4.1");
}


char* allocate_cpu_arch_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("arch");
}


char* allocate_sse41_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("sse41");
}


char* allocate_sse42_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("sse42");
}


char* allocate_avx_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("avx");
}


char* allocate_avx2_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("avx2");
}


char* allocate_avx512f_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("avx512f");
}


char* allocate_cpu_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_memory_json_object_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"memory\":{");
}


char* allocate_total_mb_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("total_mb");
}


char* allocate_available_mb_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("available_mb");
}


char* allocate_load_pct_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("load_pct");
}


char* allocate_memory_sticks_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"sticks\":[");
}


char* allocate_memory_sticks_json_array_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


wchar_t* allocate_physical_memory_inventory_query(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] =
        L"SELECT Capacity, Speed, Manufacturer, DeviceLocator, MemoryType "
        L"FROM Win32_PhysicalMemory";
    static_assert(sizeof(value) == 180U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_wql_dialect(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"WQL";
    static_assert(sizeof(value) == 8U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_json_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_memory_stick_json_object_open(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


wchar_t* allocate_capacity_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"Capacity";
    static_assert(sizeof(value) == 18U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_speed_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"Speed";
    static_assert(sizeof(value) == 12U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_manufacturer_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"Manufacturer";
    static_assert(sizeof(value) == 26U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_device_locator_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"DeviceLocator";
    static_assert(sizeof(value) == 28U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_memory_type_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"MemoryType";
    static_assert(sizeof(value) == 22U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_capacity_megabytes_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("capacity_mb");
}


char* allocate_speed_megahertz_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("speed_mhz");
}


char* allocate_unknown_memory_slot_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_memory_slot_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("slot");
}


char* allocate_unknown_memory_manufacturer_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_memory_manufacturer_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("manufacturer");
}


char* allocate_unknown_memory_type_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_ddr_memory_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DDR");
}


char* allocate_ddr2_memory_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DDR2");
}


char* allocate_ddr3_memory_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DDR3");
}


char* allocate_ddr4_memory_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DDR4");
}


char* allocate_ddr5_memory_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DDR5");
}


char* allocate_memory_type_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("type");
}


char* allocate_memory_stick_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_memory_json_section_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_motherboard_json_object_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"motherboard\":{");
}


wchar_t* allocate_baseboard_product_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"Product";
    static_assert(sizeof(value) == 16U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_baseboard_product_query(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SELECT Product FROM Win32_BaseBoard";
    static_assert(sizeof(value) == 72U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_baseboard_product_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("product");
}


wchar_t* allocate_baseboard_serial_number_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SerialNumber";
    static_assert(sizeof(value) == 26U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_baseboard_serial_number_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("serial");
}


wchar_t* allocate_bios_version_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SMBIOSBIOSVersion";
    static_assert(sizeof(value) == 36U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_bios_version_query(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SELECT SMBIOSBIOSVersion FROM Win32_BIOS";
    static_assert(sizeof(value) == 82U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_bios_version_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("bios_version");
}


wchar_t* allocate_bios_release_date_property_name(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"ReleaseDate";
    static_assert(sizeof(value) == 24U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


wchar_t* allocate_bios_release_date_query(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t value[] = L"SELECT ReleaseDate FROM Win32_BIOS";
    static_assert(sizeof(value) == 70U);
    auto* output = static_cast<wchar_t*>(::operator new(sizeof(value)));
    std::memcpy(output, value, sizeof(value));
    return output;
}


char* allocate_bios_release_date_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("bios_date");
}


char* allocate_motherboard_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_gpus_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"gpus\":[");
}


char* allocate_gpu_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_gpu_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_gpu_name_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("name");
}


char* allocate_gpu_vendor_id_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("vendor_id");
}


char* allocate_gpu_device_id_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("device_id");
}


char* allocate_gpu_vram_megabytes_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("vram_mb");
}


char* allocate_gpu_shared_megabytes_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("shared_mb");
}


char* allocate_gpu_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_gpu_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_gpu_drivers_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"gpu_drivers\":[");
}


char* allocate_display_adapter_class_registry_path(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(
        "SYSTEM\\CurrentControlSet\\Control\\Class\\"
        "{4d36e968-e325-11ce-bfc1-08002be10318}");
}


char* allocate_driver_description_registry_value_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DriverDesc");
}


char* allocate_driver_version_registry_value_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DriverVersion");
}


char* allocate_driver_date_registry_value_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("DriverDate");
}


char* allocate_gpu_driver_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_gpu_driver_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_gpu_driver_description_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("desc");
}


char* allocate_gpu_driver_version_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("version");
}


char* allocate_gpu_driver_date_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("date");
}


char* allocate_gpu_driver_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_gpu_drivers_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_hags_enabled_json_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"hags_enabled\":");
}


char* allocate_json_true_for_hags(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("true");
}


char* allocate_json_false_for_hags(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("false");
}


char* allocate_unknown_d3d11_feature_level_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_d3d11_feature_level_9_1_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("9.1");
}


char* allocate_d3d11_feature_level_9_2_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("9.2");
}


char* allocate_d3d11_feature_level_9_3_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("9.3");
}


char* allocate_d3d11_feature_level_10_0_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("10.0");
}


char* allocate_d3d11_feature_level_10_1_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("10.1");
}


char* allocate_d3d11_feature_level_11_0_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("11.0");
}


char* allocate_d3d11_feature_level_11_1_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("11.1");
}


char* allocate_d3d11_feature_level_12_0_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("12.0");
}


char* allocate_d3d11_feature_level_12_1_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("12.1");
}


char* allocate_d3d11_feature_level_12_2_or_later_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("12.2+");
}


char* allocate_d3d11_feature_level_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"d3d11_feature_level\":");
}


char* allocate_displays_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"displays\":[");
}


char* allocate_enum_display_devices_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("EnumDisplayDevicesA");
}


char* allocate_user32_for_enum_display_devices_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("user32.dll");
}




char* allocate_enum_display_settings_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("EnumDisplaySettingsA");
}


char* allocate_user32_for_enum_display_settings_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("user32.dll");
}


char* allocate_display_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_display_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_display_device_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("device");
}


char* allocate_display_width_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("width");
}


char* allocate_display_height_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("height");
}


char* allocate_display_refresh_hz_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hz");
}


char* allocate_display_bits_per_pixel_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("bpp");
}


char* allocate_display_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_displays_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_monitor_serials_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"monitor_serials\":[");
}


char* allocate_setup_di_get_class_devs_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiGetClassDevsA");
}


char* allocate_setupapi_for_get_class_devs_a(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_empty_monitor_serials_json_array_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_setup_di_enum_device_info_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiEnumDeviceInfo");
}


char* allocate_setupapi_for_enum_device_info(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_setup_di_open_dev_reg_key_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiOpenDevRegKey");
}


char* allocate_setupapi_for_open_dev_reg_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_edid_registry_value_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("EDID");
}


char* allocate_default_monitor_serial(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("0000000000001");
}


char* allocate_monitor_serial_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_monitor_serial_json_quote_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"");
}


char* allocate_monitor_serial_json_quote_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"");
}


char* allocate_setup_di_destroy_device_info_list_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiDestroyDeviceInfoList");
}


char* allocate_setupapi_for_destroy_device_info_list(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_monitor_serials_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_dwm_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"dwm\":{");
}


char* allocate_dwm_composition_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("composition");
}


char* allocate_refresh_hz_format(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%.2f");
}


char* allocate_dwm_json_property_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_refresh_hz_json_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"refresh_hz\":");
}


char* allocate_dwm_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_storage_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"storage\":{");
}


char* allocate_storage_drives_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"drives\":[");
}


wchar_t* allocate_disk_drive_inventory_query(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(
        L"SELECT Model, SerialNumber, InterfaceType, MediaType, Size FROM Win32_DiskDrive");
}


wchar_t* allocate_disk_wql_dialect(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"WQL");
}


char* allocate_disk_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_disk_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


wchar_t* allocate_disk_model_property_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"Model");
}


wchar_t* allocate_disk_serial_number_property_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"SerialNumber");
}


wchar_t* allocate_disk_interface_type_property_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"InterfaceType");
}


wchar_t* allocate_disk_media_type_property_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"MediaType");
}


wchar_t* allocate_disk_size_property_name(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"Size");
}


char* allocate_unknown_disk_model_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_empty_disk_serial_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("");
}


char* allocate_unknown_disk_interface_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_unknown_disk_media_type_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_unknown_disk_size_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_nvme_storage_classification(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("NVMe");
}


char* allocate_nvme_lowercase_storage_classification(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("nvme");
}


char* allocate_scsi_disk_interface_marker(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SCSI");
}


char* allocate_nvme_ssd_storage_type(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("NVMe SSD");
}


char* allocate_fixed_disk_media_marker(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Fixed");
}


char* allocate_ssd_disk_media_marker(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SSD");
}


char* allocate_sata_ssd_storage_type(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SATA SSD");
}


char* allocate_removable_disk_media_marker_lowercase(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("removable");
}


char* allocate_removable_disk_media_marker(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Removable");
}


char* allocate_removable_storage_type(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Removable");
}


char* allocate_disk_model_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("model");
}


char* allocate_disk_serial_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("serial");
}


char* allocate_disk_interface_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("interface");
}


char* allocate_disk_type_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("type");
}


char* allocate_disk_size_gigabytes_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("size_gb");
}


char* allocate_disk_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_storage_volumes_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("],\"volumes\":[");
}


char* allocate_volume_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_volume_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_volume_letter_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("letter");
}


char* allocate_volume_total_gigabytes_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("total_gb");
}


char* allocate_volume_free_gigabytes_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("free_gb");
}


char* allocate_volume_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_storage_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]}");
}


char* allocate_usb_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"usb\":{");
}


wchar_t* allocate_usb_controller_device_wmi_query(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(
        L"SELECT Name, DeviceID FROM Win32_USBControllerDevice");
}


wchar_t* allocate_usb_controller_device_wmi_dialect(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"WQL");
}


char* allocate_usb_device_count_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("device_count");
}


char* allocate_usb_hubs_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"hubs\":[");
}


wchar_t* allocate_usb_hub_wmi_query(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"SELECT Name FROM Win32_USBHub");
}


wchar_t* allocate_usb_hub_wmi_dialect(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"WQL");
}


wchar_t* allocate_usb_hub_name_property(const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"Name");
}


char* allocate_usb_hub_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_usb_hubs_array_and_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]}");
}


char* allocate_hid_mice_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"mice\":[");
}


char* allocate_hid_d_get_hid_guid_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidD_GetHidGuid");
}


char* allocate_hid_for_get_hid_guid(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_setup_di_enum_device_interfaces_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiEnumDeviceInterfaces");
}


char* allocate_setupapi_for_enum_device_interfaces(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_setup_di_get_device_interface_detail_a_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SetupDiGetDeviceInterfaceDetailA");
}


char* allocate_setupapi_for_get_device_interface_detail_a(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("setupapi.dll");
}


char* allocate_create_file_a_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("CreateFileA");
}


char* allocate_kernel32_for_create_file_a(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("kernel32.dll");
}


char* allocate_hid_d_get_attributes_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidD_GetAttributes");
}


char* allocate_hid_for_get_attributes(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_hid_d_get_preparsed_data_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidD_GetPreparsedData");
}


char* allocate_hid_for_get_preparsed_data(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_hid_p_get_caps_export_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidP_GetCaps");
}


char* allocate_hid_for_get_caps(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_hid_d_get_product_string_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidD_GetProductString");
}


char* allocate_hid_for_get_product_string(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_hid_mouse_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_hid_mouse_json_object_open(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_unknown_hid_product_name(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_hid_mouse_name_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("name");
}


char* allocate_hid_mouse_vendor_id_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("vid");
}


char* allocate_hid_mouse_product_id_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("pid");
}


char* allocate_hid_mouse_report_size_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("report_size");
}


char* allocate_hid_mouse_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_hid_d_free_preparsed_data_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("HidD_FreePreparsedData");
}


char* allocate_hid_for_free_preparsed_data(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hid.dll");
}


char* allocate_hid_mice_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_power_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"power\":{");
}


char* allocate_custom_power_plan_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Custom");
}


char* allocate_high_performance_power_plan_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("High Performance");
}


char* allocate_balanced_power_plan_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Balanced");
}


char* allocate_power_saver_plan_label(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Power Saver");
}


char* allocate_ultimate_performance_power_plan_label(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Ultimate Performance");
}


char* allocate_power_plan_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("plan");
}


char* allocate_power_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_timer_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"timer\":{");
}


char* allocate_ntdll_for_query_timer_resolution(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("ntdll.dll");
}


char* allocate_nt_query_timer_resolution_export_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("NtQueryTimerResolution");
}


char* allocate_timer_current_resolution_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%.4f");
}


char* allocate_timer_current_milliseconds_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("\"current_ms\":");
}


char* allocate_timer_minimum_resolution_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%.4f");
}


char* allocate_timer_minimum_milliseconds_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"min_ms\":");
}


char* allocate_timer_maximum_resolution_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%.4f");
}


char* allocate_timer_maximum_milliseconds_json_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"max_ms\":");
}


char* allocate_timer_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_processes_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"processes\":{");
}


char* allocate_process_count_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("process_count");
}


char* allocate_thread_count_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("thread_count");
}


char* allocate_processes_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_antivirus_json_array_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"antivirus\":[");
}


wchar_t* allocate_security_center2_wmi_namespace(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"ROOT\\SecurityCenter2");
}


wchar_t* allocate_antivirus_wmi_query_dialect(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"WQL");
}


wchar_t* allocate_antivirus_display_name_property(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"displayName");
}


wchar_t* allocate_antivirus_product_state_property(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    return allocate_wide_literal_copy(L"productState");
}


char* allocate_unknown_antivirus_product_name(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Unknown");
}


char* allocate_antivirus_json_item_comma(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",");
}


char* allocate_antivirus_json_object_open(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{");
}


char* allocate_antivirus_name_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("name");
}


char* allocate_antivirus_enabled_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("enabled");
}


char* allocate_antivirus_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_antivirus_json_array_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("]");
}


char* allocate_game_json_object_prefix(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"game\":{");
}


char* allocate_game_bar_registry_subkey(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Software\\Microsoft\\GameBar");
}


char* allocate_allow_auto_game_mode_registry_value(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("AllowAutoGameMode");
}


char* allocate_game_mode_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("game_mode");
}


char* allocate_auto_game_mode_enabled_registry_value(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("AutoGameModeEnabled");
}


char* allocate_auto_game_mode_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("auto_game_mode");
}


char* allocate_game_config_store_registry_subkey(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("System\\GameConfigStore");
}


char* allocate_game_dvr_enabled_registry_value(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("GameDVR_Enabled");
}


char* allocate_game_dvr_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("game_dvr");
}


char* allocate_game_dvr_fse_behavior_mode_registry_value(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("GameDVR_FSEBehaviorMode");
}


char* allocate_fse_behavior_mode_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("fse_behavior_mode");
}


char* allocate_game_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_uptime_seconds_json_field_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"uptime_seconds\":");
}


char* allocate_unsigned_long_long_decimal_format(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("%llu");
}


char* allocate_pagefile_json_object_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"pagefile\":{");
}


char* allocate_pagefile_total_mb_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("total_mb");
}


char* allocate_pagefile_available_mb_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("available_mb");
}


char* allocate_pagefile_total_virtual_mb_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("total_virtual_mb");
}


char* allocate_pagefile_avail_virtual_mb_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("avail_virtual_mb");
}


char* allocate_pagefile_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_network_json_object_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"network\":{");
}


char* allocate_tcpip_parameters_registry_subkey(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(
        "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters");
}


char* allocate_hostname_registry_value(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Hostname");
}


char* allocate_hostname_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("hostname");
}


char* allocate_network_json_object_close(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_firmware_json_object_prefix(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(",\"firmware\":{");
}


char* allocate_firmware_environment_zero_vendor_guid(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("{00000000-0000-0000-0000-000000000000}");
}


char* allocate_legacy_bios_boot_mode(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("Legacy BIOS");
}


char* allocate_uefi_boot_mode(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("UEFI");
}


char* allocate_boot_mode_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("boot_mode");
}


char* allocate_secure_boot_state_registry_subkey(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy(
        "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State");
}


char* allocate_uefi_secure_boot_enabled_registry_value(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("UEFISecureBootEnabled");
}


char* allocate_secure_boot_json_key(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("secure_boot");
}


char* allocate_tpm_service_registry_subkey(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("SYSTEM\\CurrentControlSet\\Services\\TPM");
}


char* allocate_tpm_json_key(const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("tpm");
}


char* allocate_firmware_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}


char* allocate_host_environment_json_object_close(
    const std::uint8_t* protected_source) {
    (void)protected_source;
    return allocate_literal_copy("}");
}

}
