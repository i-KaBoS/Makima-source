#pragma once

#include "makima/application/common.hpp"
#include "makima/application/events.hpp"

#include <filesystem>
#include <functional>
#include <optional>

namespace makima::application {

class SyncClient;

struct UpdateOffer {
    bool available{};
    std::string current_version;
    std::string offered_version;
    std::uint64_t download_bytes{};
};

struct UpdatePackage {
    std::filesystem::path staged_file;
    Hash256 sha256{};
};

struct UpdateReplacementPaths {
    std::filesystem::path staged;
    std::filesystem::path previous;
};

[[nodiscard]] UpdateReplacementPaths update_replacement_paths(
    const std::filesystem::path& executable);

class IUpdateSource {
public:
    using Progress = std::function<void(unsigned percent, std::string_view status)>;
    virtual ~IUpdateSource() = default;
    virtual UpdateOffer check() = 0;
    virtual UpdatePackage download(const UpdateOffer& offer, Progress progress) = 0;
};

class IUpdateInstaller {
public:
    virtual ~IUpdateInstaller() = default;
    virtual void verify_stage_and_restart(const UpdatePackage& package) = 0;
};

class UpdateCoordinator {
public:
    UpdateCoordinator(
        IUpdateSource& source,
        IUpdateInstaller& installer,
        IEventSink& events,
        const SyncClient* session = nullptr)
        : source_(source), installer_(installer), events_(events), session_(session) {}

    UpdateOffer check();
    OperationResult install();
    bool busy() const noexcept { return busy_; }

private:
    IUpdateSource& source_;
    IUpdateInstaller& installer_;
    IEventSink& events_;
    const SyncClient* session_{};
    std::optional<UpdateOffer> offer_;
    bool busy_{};
};



[[nodiscard]] OperationResult start_update_worker(UpdateCoordinator& coordinator) noexcept;

}
