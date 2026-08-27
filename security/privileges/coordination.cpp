#include "security/privileges/privileges.hpp"
#include "telemetry/reporting/reporting.hpp"

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
#include <bcrypt.h>
#include "digest.hpp"

namespace makima::security::privileges {

void clear_sensitive_privilege_material(void* memory, std::size_t size) noexcept;





bool enable_named_privilege(const wchar_t* privilege_name) noexcept {
    if (privilege_name == nullptr) return false;

    HANDLE token = nullptr;
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token)) {
        return false;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilege_name, &luid)) {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES value{};
    value.PrivilegeCount = 1;
    value.Privileges[0].Luid = luid;
    value.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    const bool adjusted = AdjustTokenPrivileges(
        token, FALSE, &value, sizeof(value), nullptr, nullptr) != FALSE;
    CloseHandle(token);
    return adjusted;
}

void derive_hmac_v2_digest(
    const std::byte* key,
    std::size_t key_size,
    std::byte* digest) noexcept {
    if (key == nullptr || key_size == 0 || digest == nullptr) return;

    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status >= 0) {
        status = BCryptCreateHash(
            algorithm,
            &hash,
            nullptr,
            0,
            const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(key)),
            static_cast<ULONG>(key_size),
            0);
    }
    constexpr std::string_view label = "makima-hmac-v2";
    if (status >= 0) {
        status = BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(const_cast<char*>(label.data())),
            static_cast<ULONG>(label.size()),
            0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(
            hash, reinterpret_cast<PUCHAR>(digest), 32, 0);
    }
    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        clear_sensitive_privilege_material(digest, 32);
    }
}

}
