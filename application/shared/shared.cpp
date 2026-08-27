#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>
#include "pipelines.hpp"

namespace makima::application::shared {

static bool append_json_escape(std::string& output, std::string_view input) {
    constexpr char hex[] = "0123456789abcdef";
    for (const unsigned char value : input) {
        switch (value) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (value < 0x20U) {
                output += "\\u00";
                output.push_back(hex[value >> 4U]);
                output.push_back(hex[value & 0x0fU]);
            } else {
                output.push_back(static_cast<char>(value));
            }
        }
    }
    return true;
}



static void append_quoted_json_text(
    std::string& output,
    std::string_view input) {
    output.push_back('"');
    append_json_escape(output, input);
    output.push_back('"');
}

void append_serialized_request_collection(
    std::string* output,
    const std::string_view* values,
    std::size_t value_count) {
    if (output == nullptr || (values == nullptr && value_count != 0)) return;
    bool first = true;
    for (std::size_t index = 0; index < value_count; ++index) {
        if (!std::exchange(first, false)) output->push_back(',');
        append_quoted_json_text(*output, values[index]);
    }
}

}
