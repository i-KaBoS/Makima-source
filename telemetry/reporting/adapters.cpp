#include "telemetry/reporting/reporting.hpp"

#include <cctype>
#include <string>
#include <string_view>

namespace makima::telemetry::reporting {

std::string normalize_security_event_name(std::string_view event_name) {
    std::string normalized;
    normalized.reserve(event_name.size());
    for (const unsigned char value : event_name) {
        if (std::isalnum(value) || value == '.' || value == '_' || value == '-') {
            normalized.push_back(static_cast<char>(value));
        }
    }
    return normalized;
}

}
