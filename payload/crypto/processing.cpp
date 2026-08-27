#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace makima::payload::crypto {
namespace {

struct EccPublicBlob final {
    BCRYPT_ECCKEY_BLOB header{};
    std::array<std::byte, 32> x{};
    std::array<std::byte, 32> y{};
};

static_assert(sizeof(EccPublicBlob) == 0x48);

struct BcryptKeyAgreementApi final {
    HMODULE module{};
    decltype(&BCryptGenerateKeyPair) generate_key_pair{};
    decltype(&BCryptFinalizeKeyPair) finalize_key_pair{};
    decltype(&BCryptExportKey) export_key{};
    decltype(&BCryptImportKeyPair) import_key_pair{};
    decltype(&BCryptSecretAgreement) secret_agreement{};
    decltype(&BCryptDeriveKey) derive_key{};
    decltype(&BCryptDestroySecret) destroy_secret{};

    [[nodiscard]] bool ready() const noexcept {
        return module != nullptr && generate_key_pair != nullptr &&
               finalize_key_pair != nullptr && export_key != nullptr &&
               import_key_pair != nullptr && secret_agreement != nullptr &&
               derive_key != nullptr && destroy_secret != nullptr;
    }
};

HMODULE bcrypt_module{};
decltype(&BCryptGenerateKeyPair) bcrypt_generate_key_pair{};
decltype(&BCryptFinalizeKeyPair) bcrypt_finalize_key_pair{};
decltype(&BCryptExportKey) bcrypt_export_key{};
decltype(&BCryptImportKeyPair) bcrypt_import_key_pair{};
decltype(&BCryptSecretAgreement) bcrypt_secret_agreement{};
decltype(&BCryptDeriveKey) bcrypt_derive_key{};
decltype(&BCryptDestroySecret) bcrypt_destroy_secret{};

[[nodiscard]] HMODULE ensure_bcrypt_module() noexcept {
    if (bcrypt_module == nullptr) {
        bcrypt_module = LoadLibraryA("bcrypt.dll");
    }
    return bcrypt_module;
}



void resolve_bcrypt_generate_key_pair_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_generate_key_pair = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_generate_key_pair)>(
              GetProcAddress(module, "BCryptGenerateKeyPair"));
}


void resolve_bcrypt_finalize_key_pair_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_finalize_key_pair = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_finalize_key_pair)>(
              GetProcAddress(module, "BCryptFinalizeKeyPair"));
}


void resolve_bcrypt_export_key_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_export_key = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_export_key)>(
              GetProcAddress(module, "BCryptExportKey"));
}


void resolve_bcrypt_import_key_pair_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_import_key_pair = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_import_key_pair)>(
              GetProcAddress(module, "BCryptImportKeyPair"));
}


void resolve_bcrypt_secret_agreement_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_secret_agreement = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_secret_agreement)>(
              GetProcAddress(module, "BCryptSecretAgreement"));
}


void resolve_bcrypt_derive_key_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_derive_key = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_derive_key)>(
              GetProcAddress(module, "BCryptDeriveKey"));
}


void resolve_bcrypt_destroy_secret_import() noexcept {
    const HMODULE module = ensure_bcrypt_module();
    bcrypt_destroy_secret = module == nullptr
        ? nullptr
        : reinterpret_cast<decltype(bcrypt_destroy_secret)>(
              GetProcAddress(module, "BCryptDestroySecret"));
}

[[nodiscard]] const BcryptKeyAgreementApi& key_agreement_api() noexcept {
    static const BcryptKeyAgreementApi api = [] {
        resolve_bcrypt_generate_key_pair_import();
        resolve_bcrypt_finalize_key_pair_import();
        resolve_bcrypt_export_key_import();
        resolve_bcrypt_import_key_pair_import();
        resolve_bcrypt_secret_agreement_import();
        resolve_bcrypt_derive_key_import();
        resolve_bcrypt_destroy_secret_import();
        return BcryptKeyAgreementApi{
            bcrypt_module,
            bcrypt_generate_key_pair,
            bcrypt_finalize_key_pair,
            bcrypt_export_key,
            bcrypt_import_key_pair,
            bcrypt_secret_agreement,
            bcrypt_derive_key,
            bcrypt_destroy_secret};
    }();
    return api;
}

void release_ecdh_handles(EcdhSession& session) noexcept {
    if (session.private_key != nullptr) {
        BCryptDestroyKey(static_cast<BCRYPT_KEY_HANDLE>(session.private_key));
        session.private_key = nullptr;
    }
    if (session.algorithm != nullptr) {
        BCryptCloseAlgorithmProvider(
            static_cast<BCRYPT_ALG_HANDLE>(session.algorithm), 0);
        session.algorithm = nullptr;
    }
    session.initialized = false;
}

}




const wchar_t* encrypted_payload_resource_path() {
    static const wchar_t* const path = detail::allocate_payload_resource_filename_suffix(
        reinterpret_cast<const std::uint16_t*>(0x1414D8440ull));
    return path;
}


void destroy_ecdh_session(EcdhSession& session) noexcept {
    release_ecdh_handles(session);
    SecureZeroMemory(session.public_component.data(), session.public_component.size());
}



bool initialize_ecdh_session(EcdhSession& session) noexcept {
    release_ecdh_handles(session);
    session.public_component.fill(std::byte{});

    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_KEY_HANDLE private_key{};
    const auto& api = key_agreement_api();
    if (!api.ready()) {
        return false;
    }
    if (BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_ECDH_ALGORITHM, nullptr, 0) < 0) {
        return false;
    }
    constexpr wchar_t curve_name[] = L"curve25519";
    if (BCryptSetProperty(
            algorithm,
            BCRYPT_ECC_CURVE_NAME,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(curve_name)),
            sizeof(curve_name),
            0) < 0 ||
        api.generate_key_pair(algorithm, &private_key, 0xff, 0) < 0 ||
        api.finalize_key_pair(private_key, 0) < 0) {
        if (private_key != nullptr) {
            BCryptDestroyKey(private_key);
        }
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    ULONG blob_size{};
    NTSTATUS status = api.export_key(
        private_key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &blob_size, 0);
    if ((status != STATUS_SUCCESS && status != STATUS_BUFFER_TOO_SMALL) ||
        blob_size < sizeof(BCRYPT_ECCKEY_BLOB) + session.public_component.size()) {
        BCryptDestroyKey(private_key);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    try {
        std::vector<std::byte> blob(blob_size);
        ULONG written{};
        status = api.export_key(
            private_key,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            reinterpret_cast<PUCHAR>(blob.data()),
            blob_size,
            &written,
            0);
        const auto* header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(
            blob.data());
        if (status < 0 || written < sizeof(BCRYPT_ECCKEY_BLOB) + 32 ||
            header->cbKey != 0x20) {
            BCryptDestroyKey(private_key);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return false;
        }
        std::memcpy(
            session.public_component.data(),
            blob.data() + sizeof(BCRYPT_ECCKEY_BLOB),
            session.public_component.size());
        SecureZeroMemory(blob.data(), blob.size());
    } catch (...) {
        BCryptDestroyKey(private_key);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return false;
    }

    session.algorithm = algorithm;
    session.private_key = private_key;
    session.initialized = true;
    return true;
}



std::uintptr_t derive_ecdh_shared_secret(
    EcdhSession& session,
    const std::array<std::byte, 32>& peer_public_component,
    PayloadKey& shared_secret) noexcept {
    shared_secret.fill(std::byte{});
    if (!session.initialized || session.algorithm == nullptr ||
        session.private_key == nullptr) {
        return 0;
    }

    EccPublicBlob peer{};
    peer.header.dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    peer.header.cbKey = 0x20;
    peer.x = peer_public_component;

    BCRYPT_KEY_HANDLE peer_key{};
    BCRYPT_SECRET_HANDLE agreement{};
    ULONG written{};
    const auto& api = key_agreement_api();
    if (!api.ready()) {
        return 0;
    }
    NTSTATUS status = api.import_key_pair(
        static_cast<BCRYPT_ALG_HANDLE>(session.algorithm),
        nullptr,
        BCRYPT_ECCPUBLIC_BLOB,
        &peer_key,
        reinterpret_cast<PUCHAR>(&peer),
        sizeof(peer),
        0);
    if (status >= 0) {
        status = api.secret_agreement(
            static_cast<BCRYPT_KEY_HANDLE>(session.private_key),
            peer_key,
            &agreement,
            0);
    }
    if (status >= 0) {
        status = api.derive_key(
            agreement,
            BCRYPT_KDF_RAW_SECRET,
            nullptr,
            reinterpret_cast<PUCHAR>(shared_secret.data()),
            static_cast<ULONG>(shared_secret.size()),
            &written,
            0);
    }

    if (agreement != nullptr) {
        api.destroy_secret(agreement);
    }
    if (peer_key != nullptr) {
        BCryptDestroyKey(peer_key);
    }
    SecureZeroMemory(&peer, sizeof(peer));

    if (status < 0 || written != shared_secret.size()) {
        shared_secret.fill(std::byte{});
        return 0;
    }
    std::reverse(shared_secret.begin(), shared_secret.end());
    return 1;
}

}
