#pragma once

#include "makima/application/application.hpp"
#include "makima/application/sync_client.hpp"

namespace makima::application {

class IAccountExtension {
public:
    virtual ~IAccountExtension() = default;
    virtual Json discord_start() = 0;
    virtual Json discord_poll() = 0;
    virtual Json discord_cancel() = 0;
    virtual Json redeem(std::string_view key) = 0;
    virtual Json user() = 0;
    virtual Json changelogs(std::string_view slug) = 0;
};

class ProtocolAccountService final : public IAccountService {
public:
    ProtocolAccountService(
        SyncClient& sync,
        IAccountExtension& extension,
        std::string hwid,
        IAuthenticatedControlSession* control_session = nullptr)
        : sync_(sync), extension_(extension), hwid_(std::move(hwid)),
          control_session_(control_session) {}

    Json login(std::string_view email, std::string_view password) override;
    Json discord_start() override;
    Json discord_poll() override;
    Json discord_cancel() override;
    Json redeem(std::string_view key) override;
    Json user() override;
    Json subscriptions() override;
    Json changelogs(std::string_view slug) override;

private:
    SyncClient& sync_;
    IAccountExtension& extension_;
    std::string hwid_;
    IAuthenticatedControlSession* control_session_{};
    std::optional<LoginModel> login_model_;
    std::optional<Json> extension_user_;
    std::optional<Json> extension_subscriptions_;
};

}
