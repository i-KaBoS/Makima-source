#include "makima/application/credential_store.hpp"

#include "makima/application/protocol.hpp"

#include <algorithm>
#include <fstream>
#include <limits>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#endif

namespace makima::application {
namespace {

constexpr std::array<std::uint8_t, 8> credential_magic{'M', 'K', 'C', 'R', '1', 0, 0, 0};

std::span<const std::uint8_t> bytes_of(std::string_view text) {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

std::string read_text(std::span<const std::uint8_t> input, std::size_t& offset) {
    if (offset + 2 > input.size()) throw ApplicationError("truncated credential text length");
    const std::size_t length = input[offset] | (static_cast<std::size_t>(input[offset + 1]) << 8);
    offset += 2;
    if (length > input.size() - offset) throw ApplicationError("truncated credential text");
    std::string result(input.begin() + offset, input.begin() + offset + length);
    offset += length;
    return result;
}

#ifdef _WIN32
DATA_BLOB blob(std::span<const std::uint8_t> data) {
    DATA_BLOB result{};
    result.cbData = static_cast<DWORD>(data.size());
    result.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(data.data()));
    return result;
}
#endif

}

Bytes WindowsDataProtector::protect(
    std::span<const std::uint8_t> plaintext,
    std::string_view purpose) {
#ifdef _WIN32
    if (plaintext.size() > std::numeric_limits<DWORD>::max())
        throw ApplicationError("credential data is too large for DPAPI");
    DATA_BLOB input = blob(plaintext);
    DATA_BLOB entropy = blob(bytes_of(purpose));
    DATA_BLOB output{};
    if (!CryptProtectData(&input, L"Makima loader credentials", &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output))
        throw ApplicationError("CryptProtectData failed");
    Bytes result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
#else
    (void)plaintext; (void)purpose;
    throw ApplicationError("DPAPI is only available on Windows");
#endif
}

Bytes WindowsDataProtector::unprotect(
    std::span<const std::uint8_t> ciphertext,
    std::string_view purpose) {
#ifdef _WIN32
    if (ciphertext.size() > std::numeric_limits<DWORD>::max())
        throw ApplicationError("protected credential data is too large for DPAPI");
    DATA_BLOB input = blob(ciphertext);
    DATA_BLOB entropy = blob(bytes_of(purpose));
    DATA_BLOB output{};
    if (!CryptUnprotectData(&input, nullptr, &entropy, nullptr, nullptr,
            CRYPTPROTECT_UI_FORBIDDEN, &output))
        throw ApplicationError("CryptUnprotectData failed");
    Bytes result(output.pbData, output.pbData + output.cbData);
    LocalFree(output.pbData);
    return result;
#else
    (void)ciphertext; (void)purpose;
    throw ApplicationError("DPAPI is only available on Windows");
#endif
}

void FileCredentialStorage::write(std::span<const std::uint8_t> bytes) {
    if (path_.has_parent_path()) std::filesystem::create_directories(path_.parent_path());
    auto temporary = path_;
    temporary += L".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) throw ApplicationError("cannot open temporary credential file");
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        output.flush();
        if (!output) throw ApplicationError("cannot write credential file");
    }
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), path_.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        std::filesystem::remove(temporary);
        throw ApplicationError("cannot atomically replace credential file");
    }
#else
    std::error_code error;
    std::filesystem::rename(temporary, path_, error);
    if (error) { std::filesystem::remove(temporary); throw ApplicationError("cannot replace credential file"); }
#endif
}

std::optional<Bytes> FileCredentialStorage::read() const {
    std::ifstream input(path_, std::ios::binary | std::ios::ate);
    if (!input) return std::nullopt;
    const auto size = input.tellg();
    if (size < 0 || size > 1024 * 1024) throw ApplicationError("credential file has an invalid size");
    Bytes result(static_cast<std::size_t>(size));
    input.seekg(0);
    input.read(reinterpret_cast<char*>(result.data()), static_cast<std::streamsize>(result.size()));
    if (!input) throw ApplicationError("cannot read credential file");
    return result;
}

void FileCredentialStorage::erase() {
    std::error_code error;
    std::filesystem::remove(path_, error);
    if (error) throw ApplicationError("cannot delete credential file");
}

Bytes CredentialRepository::serialize(const Credentials& credentials) {
    if (credentials.email.empty() || credentials.password.empty())
        throw ApplicationError("email and password are required");
    Bytes output(credential_magic.begin(), credential_magic.end());
    const Bytes email = ProtocolCodec::pack_text(credentials.email);
    const Bytes password = ProtocolCodec::pack_text(credentials.password);
    output.insert(output.end(), email.begin(), email.end());
    output.insert(output.end(), password.begin(), password.end());
    return output;
}

Credentials CredentialRepository::deserialize(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < credential_magic.size() ||
        !std::equal(credential_magic.begin(), credential_magic.end(), bytes.begin()))
        throw ApplicationError("credential record has an invalid magic value");
    std::size_t offset = credential_magic.size();
    Credentials result{read_text(bytes, offset), read_text(bytes, offset)};
    if (offset != bytes.size()) throw ApplicationError("credential record has trailing bytes");
    if (result.email.empty() || result.password.empty()) throw ApplicationError("credential record is empty");
    return result;
}

void CredentialRepository::save(const Credentials& credentials) {
    Bytes plaintext = serialize(credentials);
    Bytes encrypted = protector_.protect(plaintext, credential_protection_label);
    storage_.write(encrypted);
    std::fill(plaintext.begin(), plaintext.end(), 0);
}

std::optional<Credentials> CredentialRepository::load() {
    const auto encrypted = storage_.read();
    if (!encrypted) return std::nullopt;
    Bytes plaintext = protector_.unprotect(*encrypted, credential_protection_label);
    try {
        Credentials result = deserialize(plaintext);
        std::fill(plaintext.begin(), plaintext.end(), 0);
        return result;
    } catch (...) {
        std::fill(plaintext.begin(), plaintext.end(), 0);
        throw;
    }
}

void CredentialRepository::erase() { storage_.erase(); }

}
