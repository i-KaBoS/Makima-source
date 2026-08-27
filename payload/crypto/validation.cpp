#include "payload/crypto/crypto.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <limits>

namespace makima::payload::crypto {



std::uintptr_t validate_payload_integrity(
    const std::byte* payload,
    std::size_t payload_size,
    const PayloadDigest& expected_digest) noexcept {
    if ((payload == nullptr && payload_size != 0) ||
        payload_size > std::numeric_limits<ULONG>::max()) {
        return 0;
    }
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    PayloadDigest digest{};
    bool valid = false;
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
        BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0) >= 0 &&
        BCryptHashData(
            hash,
            reinterpret_cast<PUCHAR>(const_cast<std::byte*>(payload)),
            static_cast<ULONG>(payload_size),
            0) >= 0 &&
        BCryptFinishHash(
            hash,
            reinterpret_cast<PUCHAR>(digest.data()),
            static_cast<ULONG>(digest.size()),
            0) >= 0) {
        unsigned difference = 0;
        for (std::size_t index = 0; index < digest.size(); ++index) {
            difference |= std::to_integer<unsigned>(
                digest[index] ^ expected_digest[index]);
        }
        valid = difference == 0;
    }
    if (hash != nullptr) {
        BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
    }
    SecureZeroMemory(digest.data(), digest.size());
    return valid ? 1 : 0;
}

}
