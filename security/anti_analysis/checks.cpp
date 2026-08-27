#include "security/anti_analysis/anti_analysis.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cwctype>
#include <string>
#include <string_view>

namespace makima::security::anti_analysis {




std::uint64_t analysis_process_blacklist_check() noexcept {



    static const wchar_t* const cheatengine =
        allocate_cheatengine_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBA16ull));
    static const wchar_t* const cheat_engine =
        allocate_cheat_engine_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBA30ull));
    static const wchar_t* const ceserver =
        allocate_ceserver_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBA4Cull));
    static const wchar_t* const artmoney =
        allocate_artmoney_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBA60ull));
    static const wchar_t* const squalr =
        allocate_squalr_process_token(
            reinterpret_cast<const std::uint16_t*>(0x1414DBA74ull));
    static const wchar_t* const x64dbg = allocate_x64dbg_process_token(
        reinterpret_cast<const std::uint16_t*>(0x1414DBA84ull));

    static const std::array<std::wstring_view, 58> blocked{{


        cheatengine, cheat_engine, ceserver, artmoney, squalr, x64dbg,



        L"x32dbg", L"ollydbg", L"windbg", L"dbgsrv",
        L"immunitydebugger", L"ida.exe", L"ida64.exe", L"ghidra",
        L"binaryninja", L"radare2", L"iaito", L"dnspy", L"dotpeek",
        L"ilspy", L"de4dot", L"pe-bear", L"cffexplorer", L"pestudio",
        L"010editor", L"processhacker",




        L"systeminformer", L"BBBBBBB", L"procexp", L"reclass", L"scylla",
        L"fiddler", L"httptoolkit", L"proxyman", L"reqable",
        L"httpanalyzer", L"httpdebuggerpro", L"httpdebugger", L"]]]]]]]]]",
        L"charles", L"burpsuite", L"echomirage", L"wireshark", L"tshark",
        L"dumpcap", L"rawcap", L"smsniff", L"networkminer", L"windump",
        L"=======", L"apimonitor", L"rohitab", L"winapioverride",
        L"spystudio", L"wpe pro", L"xenos", L"extreme injector",
        L"ghinjector"}};

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 1;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    bool allowed = true;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            std::wstring image{entry.szExeFile};
            std::transform(
                image.begin(), image.end(), image.begin(),
                [](wchar_t value) {
                    return static_cast<wchar_t>(std::towlower(value));
                });
            if (std::any_of(
                    std::begin(blocked), std::end(blocked),
                    [&image](std::wstring_view token) {
                        return image.find(token) != std::wstring::npos;
                    })) {
                allowed = false;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return allowed ? 1 : 0;
}

}
