#pragma once

#include "makima/application/credential_store.hpp"
#include "makima/application/launch_coordinator.hpp"
#include "makima/application/update_coordinator.hpp"

#include <string>
#include <utility>

namespace makima::application {

class SyncClient;

enum class UiCommand {
    ready,
    login,
    discord_start,
    discord_poll,
    discord_cancel,
    redeem,
    save_creds,
    load_creds,
    delete_creds,
    user,
    subscriptions,
    changelogs,
    launch,
    check_vm,
    check_ram,
    check_connection,
    expand_window,
    resize_window,
    minimize,
    close,
    check_update,
    do_update,
};

class IAccountService {
public:
    virtual ~IAccountService() = default;
    virtual Json login(std::string_view email, std::string_view password) = 0;
    virtual Json discord_start() = 0;
    virtual Json discord_poll() = 0;
    virtual Json discord_cancel() = 0;
    virtual Json redeem(std::string_view key) = 0;
    virtual Json user() = 0;
    virtual Json subscriptions() = 0;
    virtual Json changelogs(std::string_view slug) = 0;
};

class ISystemService {
public:
    virtual ~ISystemService() = default;
    virtual Json check_vm() = 0;
    virtual Json check_ram() = 0;
    virtual Json check_connection() = 0;
};

class IWindowService {
public:
    virtual ~IWindowService() = default;
    virtual void webview_ready() = 0;
    virtual void expand() = 0;
    virtual void resize(unsigned width, unsigned height) = 0;
    virtual void minimize() = 0;
    virtual void close() = 0;
};

class ICommandTarget {
public:
    virtual ~ICommandTarget() = default;
    virtual Json execute(UiCommand command, const Json::Object& arguments) = 0;
};

class ApplicationController final : public ICommandTarget {
public:
    ApplicationController(
        IAccountService& account,
        CredentialRepository& credentials,
        ISystemService& system,
        IWindowService& window,
        UpdateCoordinator& updates,
        AuthorizedLaunchCoordinator& launches,
        SyncClient& sync,
        std::string hardware_id)
        : account_(account), credentials_(credentials), system_(system), window_(window),
          updates_(updates), launches_(launches), sync_(sync),
          hardware_id_(std::move(hardware_id)) {}

    Json execute(UiCommand command, const Json::Object& arguments) override;

private:
    static std::string required_string(const Json::Object& args, std::string_view key);
    static unsigned required_unsigned(const Json::Object& args, std::string_view key);
    IAccountService& account_;
    CredentialRepository& credentials_;
    ISystemService& system_;
    IWindowService& window_;
    UpdateCoordinator& updates_;
    AuthorizedLaunchCoordinator& launches_;
    SyncClient& sync_;
    std::string hardware_id_;
};

class IApplicationPlatform {
public:
    virtual ~IApplicationPlatform() = default;
    virtual bool acquire_single_instance() = 0;
    virtual void initialize() = 0;
    virtual int run_message_loop() = 0;
    virtual void shutdown() noexcept = 0;
};

class ApplicationLifecycle {
public:
    explicit ApplicationLifecycle(IApplicationPlatform& platform) : platform_(platform) {}
    int run();

private:
    IApplicationPlatform& platform_;
};

}
