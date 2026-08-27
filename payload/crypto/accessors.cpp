#include "payload/crypto/crypto.hpp"
#include "payload/crypto/crypto_internal.hpp"

#include <algorithm>
#include <array>
#include <ranges>
#include <string_view>
#include <utility>

namespace makima::payload::crypto {




const std::string& no_active_subscription_message() {
    static const std::string message = detail::allocate_subscription_required_message(
        0x1414D8335ll);
    return message;
}



const std::string& payload_download_failed_message() {
    static const std::string message = detail::allocate_retry_payload_download_failure(
        0x1414D85C8ll);
    return message;
}

}
