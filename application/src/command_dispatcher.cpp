#include "makima/application/command_dispatcher.hpp"

#include <array>

namespace makima::application {
namespace {

struct CommandName { std::string_view name; UiCommand command; };

constexpr std::array<CommandName, 22> command_names{{
    {"ready", UiCommand::ready},
    {"login", UiCommand::login},
    {"discord_start", UiCommand::discord_start},
    {"discord_poll", UiCommand::discord_poll},
    {"discord_cancel", UiCommand::discord_cancel},
    {"redeem", UiCommand::redeem},
    {"save_creds", UiCommand::save_creds},
    {"load_creds", UiCommand::load_creds},
    {"delete_creds", UiCommand::delete_creds},
    {"user", UiCommand::user},
    {"subscriptions", UiCommand::subscriptions},
    {"changelogs", UiCommand::changelogs},
    {"launch", UiCommand::launch},
    {"check_vm", UiCommand::check_vm},
    {"check_ram", UiCommand::check_ram},
    {"check_connection", UiCommand::check_connection},
    {"expand_window", UiCommand::expand_window},
    {"resize_window", UiCommand::resize_window},
    {"minimize", UiCommand::minimize},
    {"close", UiCommand::close},
    {"check_update", UiCommand::check_update},
    {"do_update", UiCommand::do_update},
}};

}

std::optional<UiCommand> WebViewCommandDispatcher::command_for_name(std::string_view name) noexcept {
    for (const auto& item : command_names)
        if (item.name == name) return item.command;
    return std::nullopt;
}

std::string_view WebViewCommandDispatcher::name_for_command(UiCommand command) noexcept {
    for (const auto& item : command_names)
        if (item.command == command) return item.name;
    return {};
}

Json WebViewCommandDispatcher::make_reply(std::string id, Json result) {


    return Json::Object{{"id", std::move(id)}, {"result", std::move(result)}};
}

Json WebViewCommandDispatcher::make_error(std::string id, std::string message) {
    if (message.empty()) message = "unknown";
    return make_reply(std::move(id), Json::Object{{"error", std::move(message)}});
}

void WebViewCommandDispatcher::receive(std::string_view message) noexcept {


    std::string id;
    try {
        const Json envelope = Json::parse(message);
        if (!envelope.is_object()) throw ApplicationError("UI request must be a JSON object");
        if (envelope.bool_or("ready")) {
            target_.execute(UiCommand::ready, {});
            return;
        }
        id = envelope.string_or("id");
        const std::string name = envelope.string_or("name");
        if (id.empty() || name.empty()) throw ApplicationError("UI request is missing id or name");
        const auto command = command_for_name(name);
        if (!command || *command == UiCommand::ready) {
            throw ApplicationError("unknown_method");
        }
        Json::Object arguments;
        if (const Json* args = envelope.find("args")) {
            if (!args->is_object()) throw ApplicationError("UI args must be a JSON object");
            arguments = args->as_object();
        }
        bridge_.post_json(make_reply(id, target_.execute(*command, arguments)).dump());
    } catch (const std::exception& error) {
        bridge_.post_json(make_error(std::move(id), error.what()).dump());
    }
}

}
