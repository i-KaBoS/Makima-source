#include "security/environment/environment.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <string_view>

namespace makima::security::environment {

std::string normalize_inventory_identifier(std::string_view value) {
    std::string result{value};
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return result;
}

}
