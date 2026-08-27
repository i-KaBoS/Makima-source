#pragma once

#include "makima/application/sync_client.hpp"

namespace makima::application {

class WinHttpTransport final : public IHttpTransport {
public:
    HttpResponse post(
        std::string_view url,
        std::span<const std::uint8_t> body,
        std::chrono::milliseconds timeout) override;
};

}
