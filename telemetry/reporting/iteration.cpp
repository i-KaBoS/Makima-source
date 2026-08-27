#include "telemetry/reporting/reporting.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
#include <intrin.h>

namespace makima::telemetry::reporting {

void emit_security_telemetry(std::string_view event_name, std::string_view detail);
void append_telemetry_json_escaped_text(
    std::string* output,
    const char* input,
    std::size_t length);

static bool append_json_escape(std::string& output, std::string_view input) {
    static const char* const escaped_quote =
        detail::allocate_json_quote_escape();
    static const char* const escaped_backslash =
        detail::allocate_json_backslash_escape();
    static const char* const escaped_newline =
        detail::allocate_json_newline_escape();
    static const char* const escaped_carriage_return =
        detail::allocate_json_carriage_return_escape();
    static const char* const escaped_tab =
        detail::allocate_json_tab_escape();
    static const char* const unicode_escape_format =
        detail::allocate_json_unicode_escape_format();
    for (const unsigned char value : input) {
        switch (value) {
        case '"': output += escaped_quote; break;
        case '\\': output += escaped_backslash; break;
        case '\n': output += escaped_newline; break;
        case '\r': output += escaped_carriage_return; break;
        case '\t': output += escaped_tab; break;
        default:
            if (value < 0x20U) {
                char escape[7]{};
                std::snprintf(
                    escape,
                    sizeof(escape),
                    unicode_escape_format,
                    static_cast<unsigned int>(value));
                output += escape;
            } else {
                output.push_back(static_cast<char>(value));
            }
        }
    }
    return true;
}

void append_telemetry_json_escaped_text(
    std::string* output,
    const char* input,
    std::size_t length) {
    if (output == nullptr) return;


    (void)length;
    const std::size_t input_length = input == nullptr ? 0U : std::strlen(input);
    output->push_back('"');
    append_json_escape(
        *output,
        input == nullptr ? std::string_view{} : std::string_view{input, input_length});
    output->push_back('"');
}

[[noreturn]] void emit_fast_fail_telemetry(
    std::uint32_t code,
    const char* event_name,
    const char* check) {
    char formatted[0x100]{};
    if (check != nullptr && *check != '\0') {
        static const char* const checked_fast_fail =
            detail::allocate_checked_fast_fail_format();
        std::snprintf(
            formatted, sizeof(formatted), checked_fast_fail, check, code);
    } else {
        static const char* const anonymous_fast_fail =
            detail::allocate_anonymous_fast_fail_format();
        std::snprintf(formatted, sizeof(formatted), anonymous_fast_fail, code);
    }
    sync_capture_and_report_wrapper(event_name, 3, formatted);
    __fastfail(code);
}

}
