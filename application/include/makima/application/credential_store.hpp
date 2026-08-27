#pragma once

#include "makima/application/common.hpp"

#include <filesystem>
#include <optional>

namespace makima::application {

inline constexpr std::string_view credential_protection_label = "makima.credentials.v1";

struct Credentials {
    std::string email;
    std::string password;
};

class ISecretProtector {
public:
    virtual ~ISecretProtector() = default;
    virtual Bytes protect(std::span<const std::uint8_t> plaintext, std::string_view purpose) = 0;
    virtual Bytes unprotect(std::span<const std::uint8_t> ciphertext, std::string_view purpose) = 0;
};

class WindowsDataProtector final : public ISecretProtector {
public:
    Bytes protect(std::span<const std::uint8_t> plaintext, std::string_view purpose) override;
    Bytes unprotect(std::span<const std::uint8_t> ciphertext, std::string_view purpose) override;
};

class ICredentialStorage {
public:
    virtual ~ICredentialStorage() = default;
    virtual void write(std::span<const std::uint8_t> bytes) = 0;
    virtual std::optional<Bytes> read() const = 0;
    virtual void erase() = 0;
};

class FileCredentialStorage final : public ICredentialStorage {
public:
    explicit FileCredentialStorage(std::filesystem::path path) : path_(std::move(path)) {}
    void write(std::span<const std::uint8_t> bytes) override;
    std::optional<Bytes> read() const override;
    void erase() override;
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class CredentialRepository {
public:
    CredentialRepository(ICredentialStorage& storage, ISecretProtector& protector)
        : storage_(storage), protector_(protector) {}

    void save(const Credentials& credentials);
    std::optional<Credentials> load();
    void erase();

private:
    static Bytes serialize(const Credentials& credentials);
    static Credentials deserialize(std::span<const std::uint8_t> bytes);
    ICredentialStorage& storage_;
    ISecretProtector& protector_;
};

}
