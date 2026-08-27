#include "makima/application/account_service.hpp"

#include <utility>

namespace makima::application {

Json ProtocolAccountService::login(std::string_view email, std::string_view password) {


    try {
        AuthenticatedLoginOperation operation{
            .client = &sync_,
            .hardware_id = hwid_,
            .control_session = control_session_,
        };
        LoginModel login;
        const std::string email_text{email};
        const std::string password_text{password};
        coordinate_authenticated_login(
            &operation, &login, email_text.c_str(), password_text.c_str());
        if (!operation.succeeded) {
            throw ApplicationError(operation.error.empty()
                ? "authenticated login failed"
                : operation.error);
        }
        login_model_ = std::move(login);
        Json notifications = sync_.notifications();
        return Json::Object{
            {"success", true}, {"error", ""}, {"message", ""},
            {"notifications", std::move(notifications)}};
    } catch (const std::exception& error) {
        if (control_session_ != nullptr) control_session_->stop();
        login_model_.reset();
        return Json::Object{{"success", false}, {"message", error.what()}};
    }
}

Json ProtocolAccountService::discord_start() {
    extension_user_.reset();
    extension_subscriptions_.reset();
    if (!sync_.authenticated()) sync_.open(hwid_);
    return sync_.start_discord_authorization();
}

Json ProtocolAccountService::discord_poll() {
    Json result = extension_.discord_poll();
    if (result.string_or("status") == "success") {
        if (const Json* user = result.find("user")) {
            extension_user_ = *user;
        }
        if (const Json* subscriptions = result.find("subscriptions")) {
            extension_subscriptions_ = *subscriptions;
        }
    }
    return result;
}

Json ProtocolAccountService::discord_cancel() {
    extension_user_.reset();
    extension_subscriptions_.reset();
    return extension_.discord_cancel();
}

Json ProtocolAccountService::redeem(std::string_view key) {
    if (sync_.authenticated()) return sync_.redeem(key);
    return extension_.redeem(key);
}
Json ProtocolAccountService::user() {
    if (login_model_) {
        if (const auto cached = find_user_profile(*login_model_)) return *cached;
        return extension_.user();
    }
    if (extension_user_) return *extension_user_;
    Json user = extension_.user();
    if (!user.is_null()) return user;
    throw ApplicationError("account is not authenticated");
}

Json ProtocolAccountService::subscriptions() {



    if (login_model_) {
        Json::Array result;
        for (const auto& subscription : login_model_->subscriptions)
            result.push_back(to_json(subscription));
        return result;
    }
    if (extension_subscriptions_) return *extension_subscriptions_;
    throw ApplicationError("account is not authenticated");
}

Json ProtocolAccountService::changelogs(std::string_view slug) {
    if (login_model_) {
        if (const auto cached = find_product_changelogs(*login_model_, slug)) return *cached;
    } else if (!extension_user_) {
        throw ApplicationError("account is not authenticated");
    }
    return extension_.changelogs(slug);
}

}
