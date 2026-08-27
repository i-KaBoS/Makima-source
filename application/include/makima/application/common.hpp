#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace makima::application {

using Bytes = std::vector<std::uint8_t>;
using Hash256 = std::array<std::uint8_t, 32>;

class ApplicationError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct OperationResult {
    bool success{};
    std::string message;

    static OperationResult ok(std::string message = {}) {
        return {true, std::move(message)};
    }
    static OperationResult fail(std::string message) {
        return {false, std::move(message)};
    }
};

using Headers = std::map<std::string, std::string, std::less<>>;

}
