#pragma once

#include "makima/application/application.hpp"

#include <optional>

namespace makima::application {

class IWebViewBridge {
public:
    virtual ~IWebViewBridge() = default;
    virtual void post_json(std::string_view json) = 0;
};

class WebViewCommandDispatcher {
public:
    WebViewCommandDispatcher(ICommandTarget& target, IWebViewBridge& bridge)
        : target_(target), bridge_(bridge) {}

    void receive(std::string_view message) noexcept;
    static std::optional<UiCommand> command_for_name(std::string_view name) noexcept;
    static std::string_view name_for_command(UiCommand command) noexcept;

private:
    static Json make_reply(std::string id, Json result);
    static Json make_error(std::string id, std::string message);
    ICommandTarget& target_;
    IWebViewBridge& bridge_;
};

}
