#include "makima/application/application.hpp"
#include "makima/application/session_preflight.hpp"
#include "makima/application/sync_client.hpp"

#include <charconv>
#include <limits>

namespace makima::application {
namespace {



Json execute_login_request(
    IAccountService& account,
    const Json::Object& arguments) {
    const auto email = arguments.find("email");
    const auto password = arguments.find("password");
    if (email == arguments.end() || password == arguments.end() ||
        !email->second.is_string() || !password->second.is_string()) {
        return Json::Object{
            {"success", false}, {"error", "invalid_input"},
            {"message", "email and password are required"}};
    }
    Json result = account.login(email->second.as_string(), password->second.as_string());
    if (!result.is_object()) {
        return Json::Object{
            {"success", false}, {"error", "invalid_response"},
            {"message", "login returned an invalid result"}};
    }
    auto object = result.as_object();
    if (!object.contains("success")) object.emplace("success", false);
    if (!object.contains("error")) object.emplace("error", "");
    if (!object.contains("message")) object.emplace("message", "");
    return object;
}


Json execute_discord_start(IAccountService& account) {
    Json result = account.discord_start();
    if (!result.is_object()) return Json::Object{{"success", false}, {"url", ""}};
    return result;
}

Json execute_discord_poll(IAccountService& account) {
    Json response = account.discord_poll();
    if (!response.is_object()) {
        return Json::Object{{"status", "error"}, {"message", "invalid poll response"}};
    }
    const std::string status = response.string_or("status", "error");
    if (status == "pending" || status == "success") return response;
    auto result = response.as_object();
    result["status"] = "error";
    if (!result.contains("message")) result["message"] = "Discord sign-in failed";
    return result;
}



Json execute_redemption(IAccountService& account, const Json::Object& arguments) {
    const auto key = arguments.find("key");
    if (key == arguments.end() || !key->second.is_string() || key->second.as_string().empty())
        return Json::Object{{"success", false}};
    return account.redeem(key->second.as_string());
}


Json execute_load_credentials(CredentialRepository& credentials) {
    const auto saved = credentials.load();
    if (!saved) return Json::Object{{"ok", false}};
    return Json::Object{
        {"ok", true}, {"email", saved->email}, {"password", saved->password}};
}


Json execute_launch(
    AuthorizedLaunchCoordinator& launches,
    std::string_view slug,
    std::string_view branch) {
    const OperationResult result = launches.launch(slug, branch);
    return Json::Object{
        {"ok", result.success}, {"error", result.success ? "" : result.message}};
}


Json execute_update_check(UpdateCoordinator& updates) {
    try {
        const UpdateOffer offer = updates.check();
        return Json::Object{
            {"update_required", offer.available},
            {"current_version", offer.current_version},
            {"latest_version", offer.offered_version},
            {"size", static_cast<double>(offer.download_bytes)}};
    } catch (const std::exception&) {
        return Json::Object{
            {"error", "connection_failed"}, {"update_required", false}};
    }
}


Json execute_expand_window(IWindowService& window) {
    window.expand();
    return Json::Object{{"ok", true}};
}



Json execute_resize_window(IWindowService& window, unsigned width, unsigned height) {
    window.resize(width, height);
    return Json::Object{{"ok", true}};
}

}

std::string ApplicationController::required_string(const Json::Object& args, std::string_view key) {
    const auto it = args.find(key);
    if (it == args.end() || !it->second.is_string() || it->second.as_string().empty())
        throw ApplicationError("missing or invalid argument: " + std::string(key));
    return it->second.as_string();
}

unsigned ApplicationController::required_unsigned(const Json::Object& args, std::string_view key) {
    const auto it = args.find(key);
    if (it == args.end()) throw ApplicationError("missing argument: " + std::string(key));
    if (it->second.is_number()) {
        const double value = it->second.as_number();
        if (value < 1 || value > std::numeric_limits<unsigned>::max() || value != static_cast<unsigned>(value))
            throw ApplicationError("invalid unsigned argument: " + std::string(key));
        return static_cast<unsigned>(value);
    }
    if (it->second.is_string()) {
        unsigned result{};
        const auto& text = it->second.as_string();
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result);
        if (parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && result > 0)
            return result;
    }
    throw ApplicationError("invalid unsigned argument: " + std::string(key));
}

Json ApplicationController::execute(UiCommand command, const Json::Object& arguments) {
    switch (command) {
    case UiCommand::ready:
        window_.webview_ready();
        return true;
    case UiCommand::login:
        return execute_login_request(account_, arguments);
    case UiCommand::discord_start: return execute_discord_start(account_);
    case UiCommand::discord_poll: return execute_discord_poll(account_);
    case UiCommand::discord_cancel: return account_.discord_cancel();
    case UiCommand::redeem: return execute_redemption(account_, arguments);
    case UiCommand::save_creds:
        credentials_.save({required_string(arguments, "email"), required_string(arguments, "password")});
        return Json::Object{{"success", true}};
    case UiCommand::load_creds: {
        return execute_load_credentials(credentials_);
    }
    case UiCommand::delete_creds:
        credentials_.erase();
        return Json::Object{{"success", true}};
    case UiCommand::user: return account_.user();
    case UiCommand::subscriptions: return account_.subscriptions();
    case UiCommand::changelogs: {
        const auto it = arguments.find("slug");
        const std::string slug = it != arguments.end() && it->second.is_string() ? it->second.as_string() : "";
        return account_.changelogs(slug);
    }
    case UiCommand::launch: {
        return execute_launch(
            launches_, required_string(arguments, "slug"),
            required_string(arguments, "branch"));
    }
    case UiCommand::check_vm: {
        Json result = system_.check_vm();
        VirtualMachineAssessment additional;
        inspect_virtual_machine_indicators(&additional);
        if (additional.detected && result.is_object()) {
            auto merged = result.as_object();
            merged["detected"] = true;
            merged["is_vm"] = true;
            merged["reason"] = additional.reason;
            merged["evidence"] = additional.evidence;
            return merged;
        }
        return result;
    }
    case UiCommand::check_ram: return system_.check_ram();
    case UiCommand::check_connection:
        return sync_.probe_connection(hardware_id_);
    case UiCommand::expand_window:
        return execute_expand_window(window_);
    case UiCommand::resize_window:
        return execute_resize_window(
            window_, required_unsigned(arguments, "width"),
            required_unsigned(arguments, "height"));
    case UiCommand::minimize:
        window_.minimize(); return true;
    case UiCommand::close:
        window_.close(); return true;
    case UiCommand::check_update: {
        return execute_update_check(updates_);
    }
    case UiCommand::do_update: {
        const OperationResult result = start_update_worker(updates_);
        if (result.success) return Json::Object{{"started", true}};
        return Json::Object{{"started", false}, {"error", result.message}};
    }
    }
    throw ApplicationError("unsupported UI command");
}

int ApplicationLifecycle::run() {
    if (!platform_.acquire_single_instance()) return 2;
    try {
        platform_.initialize();
        const int code = platform_.run_message_loop();
        platform_.shutdown();
        return code;
    } catch (...) {
        platform_.shutdown();
        throw;
    }
}

}
