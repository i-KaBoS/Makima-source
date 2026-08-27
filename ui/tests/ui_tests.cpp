#include "ui/asset_loader.hpp"
#include "ui/webview2_runtime.hpp"

#include <filesystem>
#include <iostream>
#include <string>

int main() {
    int failures = 0;
    const auto check = [&](bool condition, const char* message) {
        if (!condition) {
            std::cerr << message << '\n';
            ++failures;
        }
    };
    const auto assets = makima::ui::load_assets(
        std::filesystem::path{MAKIMA_UI_ASSET_DIRECTORY});
    const auto embedded_assets = makima::ui::load_embedded_assets();
    check(assets.get("/index.html").has_value(), "index.html was not loaded");
    check(assets.get("/app.css").has_value(), "app.css was not loaded");
    check(assets.get("/app.js").has_value(), "app.js was not loaded");
    check(assets.get("/_splash.html").has_value(), "startup_check.html was not mapped to /_splash.html");
    check(assets.get("/logo.png").has_value(), "logo.png was not loaded");
    for (const auto* path : {
             "/index.html", "/app.css", "/app.js", "/_splash.html", "/logo.png"}) {
        const auto external = assets.get(path);
        const auto embedded = embedded_assets.get(path);
        check(embedded.has_value(), "embedded asset was not loaded");
        check(external && embedded && external->content == embedded->content,
              "embedded asset does not match its plaintext source");
    }
    const std::string application = makima::ui::build_inline_document(assets);
    check(application.find("<style>") != std::string::npos, "stylesheet was not embedded");
    check(application.find("window.chrome.webview") != std::string::npos,
          "WebView bridge script was not embedded");
    check(application.find("/app.css") == std::string::npos,
          "external stylesheet reference remains");
    const std::string startup = makima::ui::build_startup_document(assets);
    check(startup.find("LOGO_PLACEHOLDER") == std::string::npos,
          "startup logo placeholder remains");
    check(startup.find("data:image/png;base64,") != std::string::npos,
          "startup logo was not embedded");
    return failures == 0 ? 0 : 1;
}
