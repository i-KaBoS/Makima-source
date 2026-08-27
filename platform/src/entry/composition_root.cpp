#include "makima/platform/composition_root.hpp"

#include "makima/application/application.hpp"
#include "makima/application/command_dispatcher.hpp"
#include "makima/application/credential_store.hpp"
#include "makima/application/identity.hpp"
#include "makima/application/runtime_libraries.hpp"
#include "makima/application/sync_client.hpp"
#include "makima/application/session_preflight.hpp"
#include "makima/application/winhttp_transport.hpp"
#include "makima/platform/crypto_provider.hpp"
#include "makima/platform/control_session.hpp"
#include "makima/platform/pe_mapping_plan.hpp"
#include "makima/platform/system_services.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cwchar>
#include <fstream>
#include <limits>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace makima::platform {
namespace {

std::optional<std::vector<std::uint64_t>> parse_version(std::string_view text) {
    std::vector<std::uint64_t> components;
    while (!text.empty()) {
        const auto separator = text.find('.');
        const auto component = text.substr(0, separator);
        const auto suffix = component.find_first_not_of("0123456789");
        const auto digits = component.substr(0, suffix);
        if (digits.empty()) {
            return std::nullopt;
        }

        std::uint64_t value{};
        const auto parsed = std::from_chars(
            digits.data(), digits.data() + digits.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) {
            return std::nullopt;
        }
        components.push_back(value);
        if (suffix != std::string_view::npos || separator == std::string_view::npos) {
            break;
        }
        text.remove_prefix(separator + 1);
    }
    return components;
}

bool version_is_newer(std::string_view candidate, std::string_view current) {
    const auto candidate_components = parse_version(candidate);
    const auto current_components = parse_version(current);
    if (!candidate_components || !current_components) {
        return candidate != current;
    }

    const auto component_count =
        std::max(candidate_components->size(), current_components->size());
    for (std::size_t index = 0; index < component_count; ++index) {
        const auto candidate_value = index < candidate_components->size()
            ? (*candidate_components)[index]
            : 0;
        const auto current_value = index < current_components->size()
            ? (*current_components)[index]
            : 0;
        if (candidate_value != current_value) {
            return candidate_value > current_value;
        }
    }
    return false;
}

bool has_hash(const application::Hash256& hash) noexcept {
    return std::any_of(hash.begin(), hash.end(), [](std::uint8_t value) { return value != 0; });
}

application::Bytes read_file_bytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw application::ApplicationError("cannot open staged update package");
    }
    const auto length = input.tellg();
    if (length == std::streampos{-1}) {
        throw application::ApplicationError("cannot measure staged update package");
    }
    const auto stream_length = static_cast<std::streamoff>(length);
    const auto byte_count = static_cast<std::uintmax_t>(
        stream_length);
    if (stream_length < 0 || byte_count > std::numeric_limits<std::size_t>::max() ||
        byte_count > static_cast<std::uintmax_t>(
                         std::numeric_limits<std::streamsize>::max())) {
        throw application::ApplicationError("staged update package is too large");
    }
    application::Bytes bytes(static_cast<std::size_t>(byte_count));
    input.seekg(0);
    if (!bytes.empty() && !input.read(
            reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()))) {
        throw application::ApplicationError("cannot read staged update package");
    }
    return bytes;
}

}

application::Json ConfiguredAccountExtension::discord_start() {
    if (!configuration_.discord_user) {
        discord_state_ = DiscordState::idle;
        return application::Json::Object{
            {"success", false}, {"message", "Discord sign-in is not configured for this build"}};
    }
    discord_state_ = DiscordState::pending;
    discord_polls_remaining_ = configuration_.discord_polls_before_completion;
    return application::Json::Object{{"success", true}, {"status", "pending"}};
}

application::Json ConfiguredAccountExtension::discord_poll() {
    if (discord_state_ == DiscordState::pending && discord_polls_remaining_ != 0) {
        --discord_polls_remaining_;
    }
    if (discord_state_ == DiscordState::pending && discord_polls_remaining_ == 0) {
        discord_state_ = DiscordState::authenticated;
    }
    if (discord_state_ == DiscordState::authenticated) {
        return application::Json::Object{
            {"status", "success"},
            {"user", *configuration_.discord_user},
            {"subscriptions", configuration_.discord_subscriptions},
        };
    }
    if (discord_state_ == DiscordState::pending) {
        return application::Json::Object{{"status", "pending"}};
    }
    return application::Json::Object{
        {"status", "error"}, {"message", "Discord sign-in is not active"}};
}

application::Json ConfiguredAccountExtension::discord_cancel() {
    discord_state_ = DiscordState::cancelled;
    discord_polls_remaining_ = 0;
    return application::Json::Object{{"success", true}, {"status", "cancelled"}};
}

application::Json ConfiguredAccountExtension::redeem(std::string_view key) {
    if (key.empty()) {
        return application::Json::Object{{"success", false}, {"message", "license key is empty"}};
    }
    const auto product = configuration_.redemption_products.find(key);
    if (product == configuration_.redemption_products.end()) {
        return application::Json::Object{
            {"success", false}, {"message", "invalid or expired key"}};
    }
    if (!redeemed_keys_.insert(std::string(key)).second) {
        return application::Json::Object{
            {"success", false}, {"message", "key has already been redeemed"}};
    }
    return application::Json::Object{{"success", true}, {"product", product->second}};
}

application::Json ConfiguredAccountExtension::user() {
    if (discord_state_ == DiscordState::authenticated && configuration_.discord_user) {
        return *configuration_.discord_user;
    }
    return configuration_.user_profile;
}

application::Json ConfiguredAccountExtension::changelogs(std::string_view slug) {
    const auto entries = configuration_.changelogs.find(slug);
    return entries == configuration_.changelogs.end()
        ? application::Json{application::Json::Array{}}
        : entries->second;
}

application::UpdateOffer LocalUpdateSource::check() {
    application::UpdateOffer offer{
        .available = false,
        .current_version = current_version_,
        .offered_version = current_version_,
        .download_bytes = 0};
    if (configuration_.offered_version.empty() ||
        !version_is_newer(configuration_.offered_version, current_version_)) {
        return offer;
    }
    if (configuration_.package_source.empty() || configuration_.staging_file.empty()) {
        throw application::ApplicationError("newer update is missing a package or staging path");
    }
    if (!has_hash(configuration_.expected_sha256)) {
        throw application::ApplicationError("newer update is missing its expected SHA-256");
    }

    std::error_code error;
    const auto package_size = std::filesystem::file_size(configuration_.package_source, error);
    if (error) {
        throw application::ApplicationError("cannot inspect configured update package");
    }
    offer.available = true;
    offer.offered_version = configuration_.offered_version;
    offer.download_bytes = package_size;
    return offer;
}

application::UpdatePackage LocalUpdateSource::download(
    const application::UpdateOffer& offer,
    Progress progress) {
    if (!offer.available || offer.current_version != current_version_ ||
        offer.offered_version != configuration_.offered_version) {
        throw application::ApplicationError("update offer does not match the configured package");
    }
    if (progress) {
        progress(5, "Staging update package");
    }
    std::error_code error;
    const auto parent = configuration_.staging_file.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, error);
        if (error) {
            throw application::ApplicationError("cannot create update staging directory");
        }
    }
    if (configuration_.package_source != configuration_.staging_file) {
        std::filesystem::copy_file(
            configuration_.package_source,
            configuration_.staging_file,
            std::filesystem::copy_options::overwrite_existing,
            error);
        if (error) {
            throw application::ApplicationError("cannot stage configured update package");
        }
    }
    const auto staged_size = std::filesystem::file_size(configuration_.staging_file, error);
    if (error || staged_size != offer.download_bytes) {
        throw application::ApplicationError("staged update package size does not match its offer");
    }
    if (progress) {
        progress(100, "Update package staged");
    }
    return {configuration_.staging_file, configuration_.expected_sha256};
}

void VerifiedUpdateInstaller::verify_stage_and_restart(
    const application::UpdatePackage& package) {
    if (package.staged_file.empty() || !has_hash(package.sha256)) {
        throw application::ApplicationError("staged update package is missing verification data");
    }
    if (!hash_file_) {
        throw application::ApplicationError("update package hash provider is not configured");
    }
    if (hash_file_(package.staged_file) != package.sha256) {
        throw application::ApplicationError("staged update package SHA-256 does not match");
    }

    const auto& api = application::runtime_entry_points();
    if (api.get_system_directory == nullptr || api.delete_file == nullptr ||
        api.move_file == nullptr || api.create_process == nullptr) {
        throw application::ApplicationError("required update runtime entry point is unavailable");
    }

    std::array<wchar_t, MAX_PATH> system_directory{};
    const UINT system_length = api.get_system_directory(
        system_directory.data(), static_cast<UINT>(system_directory.size()));
    if (system_length == 0 || system_length >= system_directory.size()) {
        constexpr wchar_t fallback_system_directory[] = L"C:\\Windows\\System32";
        wcscpy_s(
            system_directory.data(),
            system_directory.size(),
            fallback_system_directory);
    }

    const std::wstring staged_name = package.staged_file.filename().wstring();
    if (staged_name.empty()) {
        throw application::ApplicationError("staged update package has no file name");
    }
    std::array<wchar_t, MAX_PATH> system_staged_buffer{};
    constexpr wchar_t system_file_format[] = L"%s\\%s";
    const int system_staged_length = swprintf_s(
        system_staged_buffer.data(),
        system_staged_buffer.size(),
        system_file_format,
        system_directory.data(),
        staged_name.c_str());
    if (system_staged_length <= 0) {
        throw application::ApplicationError("cannot format the system update path");
    }
    const std::filesystem::path system_staged{system_staged_buffer.data()};

    std::array<wchar_t, 32768> executable_buffer{};
    const DWORD executable_length = GetModuleFileNameW(
        nullptr,
        executable_buffer.data(),
        static_cast<DWORD>(executable_buffer.size()));
    if (executable_length == 0 || executable_length >= executable_buffer.size()) {
        throw application::ApplicationError("cannot resolve the current executable path");
    }
    const std::filesystem::path executable{
        std::wstring_view{executable_buffer.data(), executable_length}};
    const auto replacement = application::update_replacement_paths(executable);

    const auto remove_if_present = [&](const std::filesystem::path& path) {
        if (api.delete_file(path.c_str()) == FALSE) {
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
                throw application::ApplicationError("cannot remove an existing update file");
            }
        }
    };
    const auto move_required = [&](const std::filesystem::path& from,
                                   const std::filesystem::path& to,
                                   std::string_view failure) {
        if (api.move_file(from.c_str(), to.c_str()) == FALSE) {
            throw application::ApplicationError(std::string{failure});
        }
    };

    remove_if_present(system_staged);
    if (package.staged_file != system_staged) {
        move_required(
            package.staged_file,
            system_staged,
            "cannot move the verified update into the system staging path");
    }
    remove_if_present(replacement.previous);
    move_required(executable, replacement.previous, "cannot preserve the current executable");
    try {
        move_required(system_staged, executable, "cannot install the verified update");

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        std::wstring command_line = L"\"" + executable.wstring() + L"\"";
        if (api.create_process(
                executable.c_str(),
                command_line.data(),
                nullptr,
                nullptr,
                FALSE,
                0,
                nullptr,
                system_directory.data(),
                &startup,
                &process) == FALSE) {
            throw application::ApplicationError("cannot restart the updated executable");
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    } catch (...) {
        api.delete_file(executable.c_str());
        api.move_file(replacement.previous.c_str(), executable.c_str());
        throw;
    }
    if (restart_handler_) {
        restart_handler_(executable);
    }
}

std::filesystem::path default_credential_file() {
    std::array<wchar_t, 32768> value{};
    const auto length = GetEnvironmentVariableW(
        L"LOCALAPPDATA",
        value.data(),
        static_cast<DWORD>(value.size()));
    if (length > 0 && length < value.size()) {
        return std::filesystem::path{std::wstring_view{value.data(), length}} /
               L"Makima" / L"credentials.dat";
    }
    const auto temporary_length = GetTempPathW(
        static_cast<DWORD>(value.size()),
        value.data());
    if (temporary_length == 0 || temporary_length >= value.size()) {
        throw application::ApplicationError("cannot resolve a credential storage directory");
    }
    return std::filesystem::path{std::wstring_view{value.data(), temporary_length}} /
           L"Makima" / L"credentials.dat";
}

int run_composed_win32_application(
    application::IWebViewRuntime& webview_runtime,
    const application::IAssetProvider& assets) {
    return run_composed_win32_application(
        webview_runtime, assets, PlatformCompositionOptions{});
}

int run_composed_win32_application(
    application::IWebViewRuntime& webview_runtime,
    const application::IAssetProvider& assets,
    PlatformCompositionOptions options) {
    application::install_fatal_exception_boundary();
    CngCryptoProvider crypto;
    application::WinHttpTransport http;
    application::SystemClock clock;
    application::SyncClient sync{http, crypto, clock};
    ::makima::network::session::bind_authenticated_request_client(&sync);
    struct AuthenticatedRequestClientScope final {
        ~AuthenticatedRequestClientScope() {
            ::makima::network::session::bind_authenticated_request_client(nullptr);
        }
    } authenticated_request_client_scope;

    application::WindowsHardwareIdentity identity;
    const auto hwid = application::resolve_hwid(identity);
    if (hwid.empty()) {
        throw application::ApplicationError("cannot resolve the current Windows user SID");
    }

    ConfiguredAccountExtension account_extension{std::move(options.account_extension)};
    application::WindowsDataProtector protector;
    application::FileCredentialStorage credential_storage{
        options.credential_file.empty() ? default_credential_file() : options.credential_file};
    application::CredentialRepository credentials{credential_storage, protector};
    WindowsSystemService system{options.minimum_memory_bytes};
    ToolhelpTargetDiscovery discovery{
        options.target_images.empty()
            ? ToolhelpTargetDiscovery::default_product_images()
            : std::move(options.target_images)};
    PlanningManualMapper mapper;

    application::Win32UiHost host{webview_runtime, assets};
    application::WebViewEventSink events{host};
    ControlSession control_session{sync, host};
    application::ProtocolAccountService account{
        sync, account_extension, hwid, &control_session};
    LocalUpdateSource update_source{
        std::move(options.current_version), std::move(options.update)};
    VerifiedUpdateInstaller update_installer{
        [&](const std::filesystem::path& path) {
            return crypto.sha256(read_file_bytes(path));
        },
        std::move(options.restart_update)};
    application::UpdateCoordinator updates{update_source, update_installer, events, &sync};
    application::AuthorizedLaunchCoordinator launches{sync, discovery, mapper, events};
    application::ApplicationController controller{
        account, credentials, system, host, updates, launches, sync, hwid};
    application::WebViewCommandDispatcher dispatcher{controller, host};
    host.set_message_handler(
        [&](std::string_view message) { dispatcher.receive(message); });
    return application::ApplicationLifecycle{host}.run();
}

}
