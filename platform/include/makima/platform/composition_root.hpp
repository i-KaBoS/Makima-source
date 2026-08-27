#pragma once

#include "makima/application/account_service.hpp"
#include "makima/application/ui_host.hpp"
#include "makima/application/update_coordinator.hpp"
#include "makima/platform/target_discovery.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace makima::platform {

struct AccountExtensionConfiguration final {
    std::optional<application::Json> discord_user;
    application::Json discord_subscriptions{application::Json::Array{}};
    unsigned discord_polls_before_completion{1};
    std::map<std::string, std::string, std::less<>> redemption_products;
    application::Json user_profile;
    std::map<std::string, application::Json, std::less<>> changelogs;
};

class ConfiguredAccountExtension final : public application::IAccountExtension {
public:
    explicit ConfiguredAccountExtension(AccountExtensionConfiguration configuration = {})
        : configuration_(std::move(configuration)) {}

    application::Json discord_start() override;
    application::Json discord_poll() override;
    application::Json discord_cancel() override;
    application::Json redeem(std::string_view key) override;
    application::Json user() override;
    application::Json changelogs(std::string_view slug) override;

private:
    enum class DiscordState { idle, pending, authenticated, cancelled };

    AccountExtensionConfiguration configuration_;
    std::set<std::string, std::less<>> redeemed_keys_;
    DiscordState discord_state_{DiscordState::idle};
    unsigned discord_polls_remaining_{};
};

struct LocalUpdateConfiguration final {
    std::string offered_version;
    std::filesystem::path package_source;
    std::filesystem::path staging_file;
    application::Hash256 expected_sha256{};
};

class LocalUpdateSource final : public application::IUpdateSource {
public:
    explicit LocalUpdateSource(
        std::string current_version,
        LocalUpdateConfiguration configuration = {})
        : current_version_(std::move(current_version)),
          configuration_(std::move(configuration)) {}

    application::UpdateOffer check() override;
    application::UpdatePackage download(
        const application::UpdateOffer& offer,
        Progress progress) override;

private:
    std::string current_version_;
    LocalUpdateConfiguration configuration_;
};

class VerifiedUpdateInstaller final : public application::IUpdateInstaller {
public:
    using HashFile = std::function<application::Hash256(const std::filesystem::path&)>;
    using RestartHandler = std::function<void(const std::filesystem::path&)>;

    VerifiedUpdateInstaller(HashFile hash_file, RestartHandler restart_handler)
        : hash_file_(std::move(hash_file)), restart_handler_(std::move(restart_handler)) {}

    void verify_stage_and_restart(const application::UpdatePackage& package) override;

private:
    HashFile hash_file_;
    RestartHandler restart_handler_;
};

struct PlatformCompositionOptions {
    std::filesystem::path credential_file;
    ToolhelpTargetDiscovery::ProductImages target_images;
    std::string current_version{"3.0.0"};
    std::uint64_t minimum_memory_bytes{4ULL * 1024ULL * 1024ULL * 1024ULL};
    AccountExtensionConfiguration account_extension;
    LocalUpdateConfiguration update;
    VerifiedUpdateInstaller::RestartHandler restart_update;
};

[[nodiscard]] std::filesystem::path default_credential_file();



int run_composed_win32_application(
    application::IWebViewRuntime& webview_runtime,
    const application::IAssetProvider& assets,
    PlatformCompositionOptions options);

int run_composed_win32_application(
    application::IWebViewRuntime& webview_runtime,
    const application::IAssetProvider& assets);

}
