#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <bcrypt.h>
#include <windows.h>

#include "digest.hpp"

namespace makima::security::privileges {

bool compute_sha256(
    const void* input,
    std::size_t input_size,
    std::uint8_t digest[sha256_digest_size]) noexcept {
    if ((input == nullptr && input_size != 0) || digest == nullptr ||
        input_size > static_cast<std::size_t>(MAXULONG)) {
        return false;
    }

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status >= 0) {
        status = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
    }
    if (status >= 0 && input_size != 0) {
        status = BCryptHashData(
            hash,
            static_cast<PUCHAR>(const_cast<void*>(input)),
            static_cast<ULONG>(input_size),
            0);
    }
    if (status >= 0) {
        status = BCryptFinishHash(
            hash, digest, static_cast<ULONG>(sha256_digest_size), 0);
    }

    if (hash != nullptr) BCryptDestroyHash(hash);
    if (algorithm != nullptr) BCryptCloseAlgorithmProvider(algorithm, 0);
    return status >= 0;
}

}
