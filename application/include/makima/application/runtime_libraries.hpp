#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <powrprof.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <string_view>
#include <vector>

namespace makima::application {

class RuntimeLibraries final {
public:
    RuntimeLibraries() = default;
    ~RuntimeLibraries();
    RuntimeLibraries(const RuntimeLibraries&) = delete;
    RuntimeLibraries& operator=(const RuntimeLibraries&) = delete;
    RuntimeLibraries(RuntimeLibraries&& other) noexcept;
    RuntimeLibraries& operator=(RuntimeLibraries&& other) noexcept;

    HMODULE find(std::string_view module_name) const noexcept;

private:
    friend RuntimeLibraries load_runtime_libraries();
    struct Entry { std::string_view name; HMODULE module; };
    std::vector<Entry> entries_;
};

RuntimeLibraries load_runtime_libraries();



bool verify_loaded_winhttp_image() noexcept;

struct RuntimeEntryPoints {
    decltype(&CreateProcessW) create_process{};
    decltype(&DeleteFileW) delete_file{};
    decltype(&MoveFileW) move_file{};
    decltype(&GetSystemDirectoryW) get_system_directory{};
    decltype(&GetFirmwareEnvironmentVariableA) get_firmware_environment_variable{};
    decltype(&Thread32First) thread_first{};
    decltype(&Thread32Next) thread_next{};
    decltype(&PowerGetActiveScheme) power_get_active_scheme{};
    decltype(&CryptDecodeObjectEx) crypt_decode_object{};
    decltype(&WinHttpOpen) winhttp_open{};
    decltype(&WinHttpConnect) winhttp_connect{};
    decltype(&WinHttpOpenRequest) winhttp_open_request{};
    decltype(&WinHttpSendRequest) winhttp_send_request{};
    decltype(&WinHttpReceiveResponse) winhttp_receive_response{};
    decltype(&WinHttpCloseHandle) winhttp_close_handle{};
    decltype(&WinHttpSetOption) winhttp_set_option{};
    decltype(&WinHttpAddRequestHeaders) winhttp_add_headers{};
    decltype(&WinHttpQueryHeaders) winhttp_query_headers{};
    decltype(&WinHttpQueryOption) winhttp_query_option{};
    decltype(&WinHttpSetTimeouts) winhttp_set_timeouts{};
    decltype(&WinHttpWebSocketClose) websocket_close{};
    decltype(&WinHttpWebSocketCompleteUpgrade) websocket_complete_upgrade{};
    decltype(&WinHttpWebSocketReceive) websocket_receive{};
    decltype(&WinHttpWebSocketSend) websocket_send{};
    decltype(&BCryptGenRandom) bcrypt_random{};
    decltype(&BCryptOpenAlgorithmProvider) bcrypt_open_algorithm{};
    decltype(&BCryptSetProperty) bcrypt_set_property{};
    decltype(&BCryptGenerateSymmetricKey) bcrypt_generate_key{};
    decltype(&BCryptEncrypt) bcrypt_encrypt{};
};

RuntimeEntryPoints resolve_runtime_entry_points(const RuntimeLibraries& libraries);
const RuntimeEntryPoints& runtime_entry_points();

}
