#include "telemetry/exceptions/exceptions.hpp"

#include <algorithm>

namespace makima::telemetry::exceptions {

char* allocate_unhandled_exception_event_name() {
    constexpr char event_name[] = "loader.unhandled_exception";
    static_assert(sizeof(event_name) == 0x1b);
    auto* decoded_name = new char[sizeof(event_name)];
    std::copy_n(event_name, sizeof(event_name), decoded_name);
    return decoded_name;
}

}

