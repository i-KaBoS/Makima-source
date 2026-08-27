#include "makima/application/launch_coordinator.hpp"

#include <algorithm>

namespace makima::application {
namespace {

std::uint32_t read_u32(std::span<const std::uint8_t> input, std::size_t offset) {
    if (offset + 4 > input.size()) throw ApplicationError("portable executable header is truncated");
    std::uint32_t result = 0;
    for (unsigned index = 0; index < 4; ++index)
        result |= static_cast<std::uint32_t>(input[offset + index]) << (index * 8);
    return result;
}

}

void PortableExecutableValidator::validate(std::span<const std::uint8_t> image) {
    if (image.size() < 0x40 || image[0] != 'M' || image[1] != 'Z')
        throw ApplicationError("downloaded payload is not a DOS/PE image");
    const std::uint32_t pe_offset = read_u32(image, 0x3c);
    if (pe_offset > image.size() - 4 || image[pe_offset] != 'P' || image[pe_offset + 1] != 'E' ||
        image[pe_offset + 2] != 0 || image[pe_offset + 3] != 0)
        throw ApplicationError("downloaded payload has an invalid PE signature");
}

void AuthorizedLaunchCoordinator::progress(
    std::string_view title,
    std::string_view detail,
    unsigned percent) {
    events_.publish("launch_progress", Json::Object{{"title", std::string(title)},
        {"sub", std::string(detail)}, {"percent", static_cast<double>(percent)}});
}

OperationResult AuthorizedLaunchCoordinator::launch(std::string_view slug, std::string_view branch) {
    if (busy_) return OperationResult::fail("a launch is already running");
    if (slug.empty()) return OperationResult::fail("product slug cannot be empty");
    if (branch.empty()) branch = "stable";
    busy_ = true;
    struct Reset { bool& value; ~Reset() { value = false; } } reset{busy_};
    try {
        progress("Authorizing", "Requesting an authorized payload", 10);
        AuthorizedPayload payload = payloads_.download_authorized(slug, branch);
        progress("Validating", "Checking payload integrity and format", 45);
        PortableExecutableValidator::validate(payload.image);
        progress("Waiting", "Waiting for the target application", 65);
        const auto target = discovery_.wait_for_target(slug, target_timeout_);
        if (!target || target->process_id == 0)
            return OperationResult::fail("target application was not found before the timeout");
        progress("Launching", "Mapping the authorized payload", 85);
        OperationResult mapped = mapper_.map_image(target->process_id, payload.image);
        if (!mapped.success) return mapped;
        progress("Ready", "Launch completed", 100);
        return OperationResult::ok(mapped.message.empty() ? "launch completed" : mapped.message);
    } catch (const std::exception& error) {
        events_.publish("notification", Json::Object{{"icon", "error"}, {"title", "Launch failed"},
            {"message", error.what()}});
        return OperationResult::fail(error.what());
    }
}

}
