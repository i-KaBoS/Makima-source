#include "makima/application/update_coordinator.hpp"
#include "makima/application/sync_client.hpp"

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <memory>
#include <new>
#include <process.h>
#include <windows.h>

namespace makima::application {
namespace {

std::atomic<UpdateCoordinator*> registered_update_coordinator{};






unsigned __stdcall update_worker_entry(void* raw_token) noexcept {
    const std::unique_ptr<std::byte> token{static_cast<std::byte*>(raw_token)};
    if (UpdateCoordinator* coordinator =
            registered_update_coordinator.load(std::memory_order_acquire)) {
        (void)coordinator->install();
    }
    return 0U;
}

enum class UpdateStage {
    request_build,
    build,
    download,
    write,
    install,
    finalize,
};

std::string_view update_failure(UpdateStage stage) noexcept {
    switch (stage) {
    case UpdateStage::request_build: return "Failed to request update build.";
    case UpdateStage::build: return "Build failed on server.";
    case UpdateStage::download: return "Failed to download update.";
    case UpdateStage::write: return "Failed to write update file.";
    case UpdateStage::install: return "Failed to replace executable.";
    case UpdateStage::finalize: return "Failed to rename current executable.";
    }
    return "Incomplete write.";
}

std::string_view classified_update_failure(UpdateStage stage, std::string_view detail) noexcept {
    if (stage == UpdateStage::build && detail.find("timeout") != detail.npos) {
        return "Build timed out.";
    }
    if (stage == UpdateStage::write && detail.find("incomplete") != detail.npos) {
        return "Incomplete write.";
    }
    return update_failure(stage);
}

void publish_update_stage(IEventSink& events, unsigned percent, std::string_view status) {


    events.publish("update_progress", Json::Object{
        {"percent", static_cast<double>(percent)}, {"status", std::string(status)}});
}

}

OperationResult start_update_worker(UpdateCoordinator& coordinator) noexcept {


    std::unique_ptr<std::byte> token{new (std::nothrow) std::byte{}};
    if (!token) return OperationResult::fail("failed to allocate update worker");

    registered_update_coordinator.store(&coordinator, std::memory_order_release);
    unsigned thread_id = 0;
    const std::uintptr_t thread = _beginthreadex(
        nullptr, 0, &update_worker_entry, token.get(), 0, &thread_id);
    if (thread == 0) {
        registered_update_coordinator.store(nullptr, std::memory_order_release);
        return OperationResult::fail("failed to start update worker");
    }
    token.release();
    CloseHandle(reinterpret_cast<HANDLE>(thread));
    return OperationResult::ok("update worker started");
}

UpdateReplacementPaths update_replacement_paths(const std::filesystem::path& executable) {
    if (executable.empty()) {
        throw ApplicationError("cannot plan replacement paths for an empty executable path");
    }
    constexpr std::string_view staged_suffix = ".new";
    constexpr std::string_view previous_suffix = ".old";
    const std::filesystem::path native_staged_suffix{std::string{staged_suffix}};
    const std::filesystem::path native_previous_suffix{std::string{previous_suffix}};
    return {
        std::filesystem::path{executable}.concat(native_staged_suffix.native()),
        std::filesystem::path{executable}.concat(native_previous_suffix.native()),
    };
}

UpdateOffer UpdateCoordinator::check() {
    if (session_ != nullptr && !session_->connected()) {
        throw ApplicationError("Not connected.");
    }
    offer_ = source_.check();
    return *offer_;
}

OperationResult UpdateCoordinator::install() {




    if (busy_) return OperationResult::fail("update is already running");
    if (session_ != nullptr && !session_->connected()) {
        return OperationResult::fail("Not connected.");
    }
    busy_ = true;
    struct Reset { bool& value; ~Reset() { value = false; } } reset{busy_};
    UpdateStage stage = UpdateStage::request_build;
    try {
        publish_update_stage(events_, 0, "Requesting build...");
        if (!offer_) offer_ = source_.check();
        if (!offer_->available) return OperationResult::fail("no update is available");
        stage = UpdateStage::build;
        publish_update_stage(events_, 10, "Building unique binary...");
        publish_update_stage(events_, 25, "Applying obfuscation...");
        stage = UpdateStage::download;
        publish_update_stage(events_, 40, "Downloading update...");
        UpdatePackage package = source_.download(*offer_, [&](unsigned percent, std::string_view status) {
            events_.publish("update_progress", Json::Object{
                {"percent", static_cast<double>(percent)}, {"status", std::string(status)}});
        });
        stage = UpdateStage::install;
        publish_update_stage(events_, 80, "Installing...");
        installer_.verify_stage_and_restart(package);
        stage = UpdateStage::finalize;
        publish_update_stage(events_, 100, "Finalizing...");

        events_.publish("update_done", Json::Object{});
        return OperationResult::ok("update staged");
    } catch (const std::exception& error) {
        const auto message = classified_update_failure(stage, error.what());
        constexpr char update_error_format[] =
            "{\"event\":\"update_error\",\"data\":{\"error\":\"%hs\"}}";
        const std::string error_text{message};
        const int length = std::snprintf(
            nullptr, 0, update_error_format, error_text.c_str());
        if (length > 0) {
            std::string document(static_cast<std::size_t>(length) + 1, '\0');
            std::snprintf(
                document.data(), document.size(), update_error_format, error_text.c_str());
            document.resize(static_cast<std::size_t>(length));
            events_.publish_serialized(document);
        }
        return OperationResult::fail(std::string(message));
    }
}

}
