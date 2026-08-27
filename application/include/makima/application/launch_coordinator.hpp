#pragma once

#include "makima/application/events.hpp"
#include "makima/application/sync_client.hpp"

#include <chrono>
#include <optional>

namespace makima::application {

struct TargetProcess {
    std::uint32_t process_id{};
    std::string image_name;
};

class ITargetDiscovery {
public:
    virtual ~ITargetDiscovery() = default;
    virtual std::optional<TargetProcess> wait_for_target(
        std::string_view product_slug,
        std::chrono::milliseconds timeout) = 0;
};

class IManualMapper {
public:
    virtual ~IManualMapper() = default;
    virtual OperationResult map_image(
        std::uint32_t process_id,
        std::span<const std::uint8_t> portable_executable) = 0;
};

class PortableExecutableValidator {
public:
    static void validate(std::span<const std::uint8_t> image);
};

class AuthorizedLaunchCoordinator {
public:
    AuthorizedLaunchCoordinator(
        IAuthorizedPayloadSource& payloads,
        ITargetDiscovery& discovery,
        IManualMapper& mapper,
        IEventSink& events,
        std::chrono::milliseconds target_timeout = std::chrono::minutes(5))
        : payloads_(payloads), discovery_(discovery), mapper_(mapper), events_(events),
          target_timeout_(target_timeout) {}

    OperationResult launch(std::string_view slug, std::string_view branch);
    bool busy() const noexcept { return busy_; }

private:
    void progress(std::string_view title, std::string_view detail, unsigned percent);
    IAuthorizedPayloadSource& payloads_;
    ITargetDiscovery& discovery_;
    IManualMapper& mapper_;
    IEventSink& events_;
    std::chrono::milliseconds target_timeout_;
    bool busy_{};
};

}
