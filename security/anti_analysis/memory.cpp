#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>

#include "security/anti_analysis/anti_analysis.hpp"

namespace makima::security::anti_analysis {


char* allocate_flush_instruction_cache(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "FlushInstructionCache";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_get_tick_count(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr char decoded_value[] = "GetTickCount";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll_for_get_tick_count(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll_for_get_thread_context(
    std::int64_t protected_source,
    std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_check_remote_debugger_present(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "CheckRemoteDebuggerPresent";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll_for_check_remote_debugger_present(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_query_full_process_image_name_w(std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "QueryFullProcessImageNameW";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


char* allocate_kernel32_dll_for_query_full_process_image_name_w(
    std::int64_t protected_source) {
    (void)protected_source;
    constexpr char decoded_value[] = "kernel32.dll";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<char*>(output);
}


wchar_t* allocate_explorer_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"explorer.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_svchost_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"svchost.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_sihost_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"sihost.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_runtime_broker_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"RuntimeBroker.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_shell_experience_host_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ShellExperienceHost.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_application_frame_host_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ApplicationFrameHost.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_cmd_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"cmd.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_powershell_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"powershell.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_pwsh_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"pwsh.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_windows_terminal_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"WindowsTerminal.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_wt_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"wt.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_chrome_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"chrome.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_msedge_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"msedge.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_firefox_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"firefox.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_opera_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"opera.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_brave_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"brave.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_vivaldi_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"vivaldi.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_iexplore_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"iexplore.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_7z_fm_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"7zFM.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_winrar_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"WinRAR.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_total_commander_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Total Commander.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_discord_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Discord.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_discord_ptb_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"DiscordPTB.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_discord_canary_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"DiscordCanary.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_telegram_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"Telegram.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_rundll32_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"rundll32.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_taskmgr_exe(std::int64_t protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"taskmgr.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_dllhost_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"dllhost.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_cheatengine_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"cheatengine";
    static_assert(sizeof(decoded_value) == 24U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_cheat_engine_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"cheat engine";
    static_assert(sizeof(decoded_value) == 26U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_ceserver_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ceserver";
    static_assert(sizeof(decoded_value) == 18U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_artmoney_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"artmoney";
    static_assert(sizeof(decoded_value) == 18U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_squalr_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"squalr";
    static_assert(sizeof(decoded_value) == 14U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}



wchar_t* allocate_x64dbg_process_token(
    const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"x64dbg";
    static_assert(sizeof(decoded_value) == 14U);
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_x32dbg(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"x32dbg";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_ollydbg(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ollydbg";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_windbg(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"windbg";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_dbgsrv(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"dbgsrv";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_immunitydebugger(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr wchar_t decoded_value[] = L"immunitydebugger";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_ida64_exe(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ida64.exe";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_ghidra(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ghidra";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_radare2(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"radare2";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_iaito(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"iaito";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_dnspy(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"dnspy";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_dotpeek(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"dotpeek";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_ilspy(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"ilspy";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_de4dot(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"de4dot";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_pe_bear(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"pe-bear";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_cffexplorer(std::int64_t protected_source, std::uint64_t auxiliary_input) {
    (void)protected_source;
    (void)auxiliary_input;
    constexpr wchar_t decoded_value[] = L"cffexplorer";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_pestudio(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"pestudio";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_010editor(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"010editor";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}


wchar_t* allocate_processhacker(const std::uint16_t* protected_source) {
    (void)protected_source;
    constexpr wchar_t decoded_value[] = L"processhacker";
    auto* output = static_cast<std::byte*>(::operator new(sizeof(decoded_value)));
    std::memcpy(output, decoded_value, sizeof(decoded_value));
    return reinterpret_cast<wchar_t*>(output);
}

}
