#pragma once

#include "makima/application/launch_coordinator.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace makima::platform {

class ToolhelpTargetDiscovery final : public application::ITargetDiscovery {
public:
    using ProductImages = std::unordered_map<std::string, std::vector<std::wstring>>;

    explicit ToolhelpTargetDiscovery(ProductImages product_images = default_product_images());

    std::optional<application::TargetProcess> wait_for_target(
        std::string_view product_slug,
        std::chrono::milliseconds timeout) override;

    static ProductImages default_product_images();

private:
    ProductImages product_images_;
};

}
