#pragma once

#include <string_view>

namespace makima::application {



[[nodiscard]] bool verify_winhttp_server_certificate(
    void* request_handle,
    std::string_view expected_host) noexcept;

}
