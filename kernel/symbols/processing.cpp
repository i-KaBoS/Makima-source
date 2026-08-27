#include "kernel/symbols/symbols.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>

namespace makima::kernel::symbols {
namespace {

constexpr std::array<std::byte, 24> cache_key_salt{{
    std::byte{0x57}, std::byte{0x62}, std::byte{0x66}, std::byte{0x00},
    std::byte{0x01}, std::byte{0x31}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x28}, std::byte{0x73}, std::byte{0x69},
    std::byte{0xfe}, std::byte{0x47}, std::byte{0x6c}, std::byte{0x65},
    std::byte{0x60}, std::byte{0x6b}, std::byte{0x6c}, std::byte{0x41},
    std::byte{0x7e}, std::byte{0x65}, std::byte{0x6d}, std::byte{0x7f},
}};

constexpr std::array<std::byte, 22> cache_name_salt{{
    std::byte{0x43}, std::byte{0x65}, std::byte{0x76}, std::byte{0x74},
    std::byte{0x46}, std::byte{0x6a}, std::byte{0x76}, std::byte{0x67},
    std::byte{0x62}, std::byte{0x62}, std::byte{0x3f}, std::byte{0x6a},
    std::byte{0x74}, std::byte{0x66}, std::byte{0x75}, std::byte{0xc0},
    std::byte{0x00}, std::byte{0x00}, std::byte{0x00}, std::byte{0x00},
    std::byte{0x00}, std::byte{0x00},
}};

template <std::size_t Size>
[[nodiscard]] std::unique_ptr<wchar_t[]> allocate_wide_literal(
    const wchar_t (&literal)[Size]) {
    auto result = std::make_unique<wchar_t[]>(Size);
    std::copy_n(literal, Size, result.get());
    return result;
}




[[nodiscard]] const wchar_t* app_repository_directory() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wide_literal(
        L"C:\\ProgramData\\Microsoft\\Windows\\AppRepository");
    return value.get();
}




[[nodiscard]] const wchar_t* app_repository_state_data_directory() {
    static const std::unique_ptr<wchar_t[]> value = allocate_wide_literal(
        L"C:\\ProgramData\\Microsoft\\Windows\\AppRepository\\StateData");
    return value.get();
}

class AlgorithmHandle final {
public:
    ~AlgorithmHandle() {
        if (value != nullptr) BCryptCloseAlgorithmProvider(value, 0);
    }
    BCRYPT_ALG_HANDLE value{};
};

class KeyHandle final {
public:
    ~KeyHandle() {
        if (value != nullptr) BCryptDestroyKey(value);
    }
    BCRYPT_KEY_HANDLE value{};
};

[[nodiscard]] std::string current_user_sid() noexcept {
    HANDLE token{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD bytes{};
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    std::vector<std::byte> storage(bytes);
    if (bytes == 0 || !GetTokenInformation(
            token, TokenUser, storage.data(), bytes, &bytes)) {
        CloseHandle(token);
        return {};
    }
    CloseHandle(token);
    LPSTR text{};
    const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
    if (!ConvertSidToStringSidA(user->User.Sid, &text)) return {};
    std::string result{text};
    LocalFree(text);
    return result;
}

[[nodiscard]] bool sha256(
    std::span<const std::byte> input,
    std::array<std::byte, 32>& output) noexcept {
    AlgorithmHandle algorithm;
    BCRYPT_HASH_HANDLE hash{};
    if (input.size() > std::numeric_limits<ULONG>::max() ||
        BCryptOpenAlgorithmProvider(
            &algorithm.value, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptCreateHash(
            algorithm.value, &hash, nullptr, 0, nullptr, 0, 0) < 0) {
        return false;
    }
    const NTSTATUS hash_status = BCryptHashData(
        hash,
        reinterpret_cast<PUCHAR>(const_cast<std::byte*>(input.data())),
        static_cast<ULONG>(input.size()),
        0);
    const NTSTATUS finish_status = hash_status < 0
        ? hash_status
        : BCryptFinishHash(
              hash,
              reinterpret_cast<PUCHAR>(output.data()),
              static_cast<ULONG>(output.size()),
              0);
    BCryptDestroyHash(hash);
    return finish_status >= 0;
}

[[nodiscard]] bool derive_cache_key(
    std::string_view identity,
    std::array<std::byte, 32>& key) noexcept {
    try {
        std::vector<std::byte> round;
        round.reserve(identity.size() + cache_key_salt.size() + 36);
        round.insert(
            round.end(),
            reinterpret_cast<const std::byte*>(identity.data()),
            reinterpret_cast<const std::byte*>(identity.data() + identity.size()));
        round.insert(round.end(), cache_key_salt.begin(), cache_key_salt.end());
        if (!sha256(round, key)) return false;
        for (std::uint32_t iteration = 0; iteration != 0x0fff; ++iteration) {
            round.clear();
            round.insert(round.end(), key.begin(), key.end());
            round.insert(
                round.end(),
                reinterpret_cast<const std::byte*>(identity.data()),
                reinterpret_cast<const std::byte*>(identity.data() + identity.size()));
            const auto* counter = reinterpret_cast<const std::byte*>(&iteration);
            round.insert(round.end(), counter, counter + sizeof(iteration));
            if (!sha256(round, key)) {
                SecureZeroMemory(round.data(), round.size());
                return false;
            }
        }
        SecureZeroMemory(round.data(), round.size());
        return true;
    } catch (...) {
        key.fill(std::byte{});
        return false;
    }
}





[[nodiscard]] std::filesystem::path cache_path(
    std::string_view identity,
    std::string_view entry_name) {
    std::vector<std::byte> name_material;
    name_material.insert(
        name_material.end(),
        reinterpret_cast<const std::byte*>(identity.data()),
        reinterpret_cast<const std::byte*>(identity.data() + identity.size()));
    name_material.insert(
        name_material.end(),
        reinterpret_cast<const std::byte*>(entry_name.data()),
        reinterpret_cast<const std::byte*>(entry_name.data() + entry_name.size()));
    name_material.insert(
        name_material.end(), cache_name_salt.begin(), cache_name_salt.end());
    std::array<std::byte, 32> digest{};
    if (!sha256(name_material, digest)) return {};
    std::wostringstream file_name;
    file_name << std::hex << std::setfill(L'0');
    for (const std::byte value : digest) {
        file_name << std::setw(2) << std::to_integer<unsigned>(value);
    }
    file_name << L".dat";
    const wchar_t* repository = app_repository_directory();
    const wchar_t* state_data = app_repository_state_data_directory();
    CreateDirectoryW(repository, nullptr);
    CreateDirectoryW(state_data, nullptr);
    return std::filesystem::path{state_data} / file_name.str();
}

[[nodiscard]] bool make_aes_cbc_key(
    std::span<const std::byte, 32> key,
    AlgorithmHandle& algorithm,
    KeyHandle& key_handle,
    std::vector<std::byte>& key_object) {
    if (BCryptOpenAlgorithmProvider(
            &algorithm.value, BCRYPT_AES_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }
    constexpr wchar_t mode[] = BCRYPT_CHAIN_MODE_CBC;
    if (BCryptSetProperty(
            algorithm.value,
            BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(mode)),
            sizeof(mode),
            0) < 0) {
        return false;
    }
    ULONG object_size{};
    ULONG written{};
    if (BCryptGetProperty(
            algorithm.value,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &written,
            0) < 0 || written != sizeof(object_size)) {
        return false;
    }
    key_object.resize(object_size);
    return BCryptGenerateSymmetricKey(
               algorithm.value,
               &key_handle.value,
               reinterpret_cast<PUCHAR>(key_object.data()),
               object_size,
               reinterpret_cast<PUCHAR>(const_cast<std::byte*>(key.data())),
               static_cast<ULONG>(key.size()),
               0) >= 0;
}



[[nodiscard]] bool decrypt_cache_payload(
    std::span<const std::byte, 32> key,
    std::array<std::byte, 16> iv,
    std::span<const std::byte> ciphertext,
    std::vector<std::byte>& plaintext) noexcept {
    plaintext.clear();
    if (ciphertext.empty() || ciphertext.size() > std::numeric_limits<ULONG>::max()) {
        return false;
    }
    std::vector<std::byte> key_object;
    try {
        AlgorithmHandle algorithm;
        KeyHandle key_handle;
        if (!make_aes_cbc_key(key, algorithm, key_handle, key_object)) {
            SecureZeroMemory(key_object.data(), key_object.size());
            SecureZeroMemory(iv.data(), iv.size());
            return false;
        }
        plaintext.resize(ciphertext.size());
        ULONG written{};
        if (BCryptDecrypt(
                key_handle.value,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(ciphertext.data())),
                static_cast<ULONG>(ciphertext.size()),
                nullptr,
                reinterpret_cast<PUCHAR>(iv.data()),
                static_cast<ULONG>(iv.size()),
                reinterpret_cast<PUCHAR>(plaintext.data()),
                static_cast<ULONG>(plaintext.size()),
                &written,
                BCRYPT_BLOCK_PADDING) < 0) {
            plaintext.clear();
            SecureZeroMemory(key_object.data(), key_object.size());
            SecureZeroMemory(iv.data(), iv.size());
            return false;
        }
        plaintext.resize(written);
        SecureZeroMemory(key_object.data(), key_object.size());
        SecureZeroMemory(iv.data(), iv.size());
        return true;
    } catch (...) {
        plaintext.clear();
        SecureZeroMemory(key_object.data(), key_object.size());
        SecureZeroMemory(iv.data(), iv.size());
        return false;
    }
}

[[nodiscard]] bool encrypt_cache_payload(
    std::span<const std::byte, 32> key,
    std::array<std::byte, 16> iv,
    std::span<const std::byte> plaintext,
    std::vector<std::byte>& ciphertext) noexcept {
    ciphertext.clear();
    if (plaintext.size() > std::numeric_limits<ULONG>::max() - 16) return false;
    std::vector<std::byte> key_object;
    try {
        AlgorithmHandle algorithm;
        KeyHandle key_handle;
        if (!make_aes_cbc_key(key, algorithm, key_handle, key_object)) {
            SecureZeroMemory(key_object.data(), key_object.size());
            SecureZeroMemory(iv.data(), iv.size());
            return false;
        }
        ciphertext.resize(plaintext.size() + 16);
        ULONG written{};
        if (BCryptEncrypt(
                key_handle.value,
                reinterpret_cast<PUCHAR>(const_cast<std::byte*>(plaintext.data())),
                static_cast<ULONG>(plaintext.size()),
                nullptr,
                reinterpret_cast<PUCHAR>(iv.data()),
                static_cast<ULONG>(iv.size()),
                reinterpret_cast<PUCHAR>(ciphertext.data()),
                static_cast<ULONG>(ciphertext.size()),
                &written,
                BCRYPT_BLOCK_PADDING) < 0) {
            ciphertext.clear();
            SecureZeroMemory(key_object.data(), key_object.size());
            SecureZeroMemory(iv.data(), iv.size());
            return false;
        }
        ciphertext.resize(written);
        SecureZeroMemory(key_object.data(), key_object.size());
        SecureZeroMemory(iv.data(), iv.size());
        return true;
    } catch (...) {
        ciphertext.clear();
        SecureZeroMemory(key_object.data(), key_object.size());
        SecureZeroMemory(iv.data(), iv.size());
        return false;
    }
}

}



std::uint64_t load_encrypted_symbol_cache(
    const std::string& symbol_key,
    const std::string& pdb_name,
    std::vector<std::byte>& plaintext) noexcept {
    plaintext.clear();
    const std::string identity = current_user_sid();
    if (identity.empty()) return 0;
    try {
        const auto path = cache_path(
            identity, symbol_key + ":" + pdb_name);
        std::ifstream stream(path, std::ios::binary | std::ios::ate);
        if (!stream) return 0;
        const auto length = stream.tellg();
        constexpr std::streamoff maximum_cache_size = 0x0c800000;
        if (length <= 16 || length > maximum_cache_size) return 0;
        std::vector<std::byte> encrypted(static_cast<std::size_t>(length));
        stream.seekg(0);
        stream.read(reinterpret_cast<char*>(encrypted.data()), length);
        if (!stream) return 0;
        std::array<std::byte, 16> iv{};
        std::copy_n(encrypted.begin(), iv.size(), iv.begin());
        std::array<std::byte, 32> key{};
        if (!derive_cache_key(identity, key)) return 0;
        const bool result = decrypt_cache_payload(
            key, iv, std::span<const std::byte>{encrypted}.subspan(iv.size()), plaintext);
        SecureZeroMemory(key.data(), key.size());
        SecureZeroMemory(encrypted.data(), encrypted.size());
        return result ? 1 : 0;
    } catch (...) {
        plaintext.clear();
        return 0;
    }
}



std::uint64_t save_encrypted_symbol_cache(
    const std::string& symbol_key,
    const std::string& pdb_name,
    std::span<const std::byte> plaintext) noexcept {
    const std::string identity = current_user_sid();
    if (identity.empty()) return 0;
    std::array<std::byte, 32> key{};
    std::array<std::byte, 16> iv{};
    try {
        if (!derive_cache_key(identity, key) ||
            BCryptGenRandom(
                nullptr,
                reinterpret_cast<PUCHAR>(iv.data()),
                static_cast<ULONG>(iv.size()),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            SecureZeroMemory(key.data(), key.size());
            SecureZeroMemory(iv.data(), iv.size());
            return 0;
        }
        std::vector<std::byte> encrypted;
        if (!encrypt_cache_payload(key, iv, plaintext, encrypted)) {
            SecureZeroMemory(key.data(), key.size());
            SecureZeroMemory(iv.data(), iv.size());
            return 0;
        }
        std::ofstream stream(
            cache_path(identity, symbol_key + ":" + pdb_name),
            std::ios::binary | std::ios::trunc);
        stream.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        stream.write(
            reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        const bool result = static_cast<bool>(stream);
        SecureZeroMemory(key.data(), key.size());
        SecureZeroMemory(iv.data(), iv.size());
        SecureZeroMemory(encrypted.data(), encrypted.size());
        return result ? 1 : 0;
    } catch (...) {
        SecureZeroMemory(key.data(), key.size());
        SecureZeroMemory(iv.data(), iv.size());
        return 0;
    }
}






[[nodiscard]] bool set_kernel_symbol_privilege(
    HANDLE token,
    const wchar_t* privilege_name,
    bool enabled) noexcept {
    if (privilege_name == nullptr || *privilege_name == L'\0') return false;

    HANDLE effective_token = token;
    const bool owns_token = effective_token == nullptr;
    if (owns_token && OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &effective_token) == FALSE) {
        return false;
    }

    LUID identifier{};
    bool result = LookupPrivilegeValueW(
                      nullptr, privilege_name, &identifier) != FALSE;
    if (result) {
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = identifier;
        privileges.Privileges[0].Attributes =
            enabled ? SE_PRIVILEGE_ENABLED : 0U;
        SetLastError(ERROR_SUCCESS);
        result = AdjustTokenPrivileges(
                     effective_token,
                     FALSE,
                     &privileges,
                     0,
                     nullptr,
                     nullptr) != FALSE &&
            GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }

    if (owns_token) CloseHandle(effective_token);
    return result;
}

}
