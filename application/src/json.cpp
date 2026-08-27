#include "makima/application/json.hpp"

#include "makima/application/common.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace makima::application {
namespace {

class Parser {
public:
    explicit Parser(std::string_view text) : text_(text) {}

    Json parse_document() {
        skip_space();
        Json value = parse_value();
        skip_space();
        if (position_ != text_.size())
            fail("unexpected trailing JSON data");
        return value;
    }

private:
    [[noreturn]] void fail(std::string_view message) const {
        throw ApplicationError(std::string(message) + " at byte " + std::to_string(position_));
    }

    void skip_space() {
        while (position_ < text_.size()) {
            const char c = text_[position_];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
                break;
            ++position_;
        }
    }

    bool consume(char expected) {
        if (position_ < text_.size() && text_[position_] == expected) {
            ++position_;
            return true;
        }
        return false;
    }

    Json parse_value() {
        skip_space();
        if (position_ >= text_.size())
            fail("expected JSON value");
        switch (text_[position_]) {
        case 'n': read_literal("null"); return nullptr;
        case 't': read_literal("true"); return true;
        case 'f': read_literal("false"); return false;
        case '"': return parse_string();
        case '{': return parse_object();
        case '[': return parse_array();
        default: return parse_number();
        }
    }

    void read_literal(std::string_view literal) {
        if (text_.substr(position_, literal.size()) != literal)
            fail("invalid JSON literal");
        position_ += literal.size();
    }

    static void append_utf8(std::string& output, unsigned value) {
        if (value <= 0x7f) {
            output.push_back(static_cast<char>(value));
        } else if (value <= 0x7ff) {
            output.push_back(static_cast<char>(0xc0 | (value >> 6)));
            output.push_back(static_cast<char>(0x80 | (value & 0x3f)));
        } else {
            output.push_back(static_cast<char>(0xe0 | (value >> 12)));
            output.push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3f)));
            output.push_back(static_cast<char>(0x80 | (value & 0x3f)));
        }
    }

    unsigned read_hex_quad() {
        if (position_ + 4 > text_.size())
            fail("truncated JSON Unicode escape");
        unsigned result = 0;
        for (int i = 0; i < 4; ++i) {
            const char c = text_[position_++];
            result <<= 4;
            if (c >= '0' && c <= '9') result |= static_cast<unsigned>(c - '0');
            else if (c >= 'a' && c <= 'f') result |= static_cast<unsigned>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') result |= static_cast<unsigned>(c - 'A' + 10);
            else fail("invalid JSON Unicode escape");
        }
        return result;
    }

    std::string parse_string() {
        if (!consume('"'))
            fail("expected JSON string");
        std::string output;
        while (position_ < text_.size()) {
            const char c = text_[position_++];
            if (c == '"')
                return output;
            if (static_cast<unsigned char>(c) < 0x20)
                fail("control character in JSON string");
            if (c != '\\') {
                output.push_back(c);
                continue;
            }
            if (position_ >= text_.size())
                fail("truncated JSON escape");
            switch (text_[position_++]) {
            case '"': output.push_back('"'); break;
            case '\\': output.push_back('\\'); break;
            case '/': output.push_back('/'); break;
            case 'b': output.push_back('\b'); break;
            case 'f': output.push_back('\f'); break;
            case 'n': output.push_back('\n'); break;
            case 'r': output.push_back('\r'); break;
            case 't': output.push_back('\t'); break;
            case 'u': append_utf8(output, read_hex_quad()); break;
            default: fail("invalid JSON escape");
            }
        }
        fail("unterminated JSON string");
    }

    Json parse_number() {
        const std::size_t start = position_;
        if (consume('-')) {}
        if (consume('0')) {
        } else {
            if (position_ >= text_.size() || text_[position_] < '1' || text_[position_] > '9')
                fail("invalid JSON number");
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9')
                ++position_;
        }
        if (consume('.')) {
            const auto fraction = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9')
                ++position_;
            if (position_ == fraction) fail("invalid JSON fraction");
        }
        if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
            ++position_;
            if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-'))
                ++position_;
            const auto exponent = position_;
            while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9')
                ++position_;
            if (position_ == exponent) fail("invalid JSON exponent");
        }
        double result{};
        const auto token = text_.substr(start, position_ - start);
        const auto conversion = std::from_chars(token.data(), token.data() + token.size(), result);
        if (conversion.ec != std::errc{} || !std::isfinite(result))
            fail("invalid JSON number");
        return result;
    }

    Json parse_object() {
        consume('{');
        Json::Object object;
        skip_space();
        if (consume('}')) return object;
        for (;;) {
            skip_space();
            std::string key = parse_string();
            skip_space();
            if (!consume(':')) fail("expected ':' after JSON member name");
            auto [_, inserted] = object.emplace(std::move(key), parse_value());
            if (!inserted) fail("duplicate JSON member");
            skip_space();
            if (consume('}')) return object;
            if (!consume(',')) fail("expected ',' between JSON members");
        }
    }

    Json parse_array() {
        consume('[');
        Json::Array array;
        skip_space();
        if (consume(']')) return array;
        for (;;) {
            array.push_back(parse_value());
            skip_space();
            if (consume(']')) return array;
            if (!consume(',')) fail("expected ',' between JSON values");
        }
    }

    std::string_view text_;
    std::size_t position_{};
};

void dump_string(std::ostringstream& output, std::string_view value) {
    output << '"';
    for (const unsigned char c : value) {
        switch (c) {
        case '"': output << "\\\""; break;
        case '\\': output << "\\\\"; break;
        case '\b': output << "\\b"; break;
        case '\f': output << "\\f"; break;
        case '\n': output << "\\n"; break;
        case '\r': output << "\\r"; break;
        case '\t': output << "\\t"; break;
        default:
            if (c < 0x20) {


                constexpr char unicode_escape_format[] = "\\u%04x";
                std::array<char, 7> escaped{};
                std::snprintf(
                    escaped.data(), escaped.size(), unicode_escape_format,
                    static_cast<unsigned>(c));
                output << escaped.data();
            } else {
                output << static_cast<char>(c);
            }
        }
    }
    output << '"';
}

void dump_value(std::ostringstream& output, const Json& value) {
    if (value.is_null()) output << "null";
    else if (value.is_bool()) output << (value.as_bool() ? "true" : "false");
    else if (value.is_number()) output << std::setprecision(17) << value.as_number();
    else if (value.is_string()) dump_string(output, value.as_string());
    else if (value.is_array()) {
        output << '[';
        bool first = true;
        for (const auto& item : value.as_array()) {
            if (!first) output << ',';
            first = false;
            dump_value(output, item);
        }
        output << ']';
    } else {
        output << '{';
        bool first = true;
        const auto append_member = [&](std::string_view key, const Json& item) {
            if (!first) output << ',';
            first = false;


            dump_string(output, key);
            output << ':';
            dump_value(output, item);
        };
        const auto& object = value.as_object();
        const auto& member_order = value.object_member_order();
        for (const auto& key : member_order) {
            if (const auto member = object.find(key); member != object.end()) {
                append_member(member->first, member->second);
            }
        }
        for (const auto& [key, item] : object) {
            if (std::find(member_order.begin(), member_order.end(), key) == member_order.end()) {
                append_member(key, item);
            }
        }
        output << '}';
    }
}

}






void extract_json_string_member(
    const std::string_view& document,
    const char* member_name,
    std::string& output) {
    const std::string quoted_name =
        std::string{"\""} + member_name + '"';
    std::size_t search_from = 0;
    while (search_from <= document.size()) {
        const std::size_t member = document.find(quoted_name, search_from);
        if (member == std::string_view::npos) return;

        std::size_t cursor = member + quoted_name.size();
        while (cursor < document.size() &&
               (document[cursor] == ' ' || document[cursor] == ':')) {
            ++cursor;
        }
        if (cursor >= document.size() || document[cursor] != '"') {
            search_from = member + 1;
            continue;
        }

        output.clear();
        ++cursor;
        while (cursor < document.size()) {
            char value = document[cursor++];
            if (value == '"') return;
            if (value == '\\' && cursor < document.size()) {
                value = document[cursor++];
                switch (value) {
                case '\\': value = '\\'; break;
                case '"': value = '"'; break;
                case '/': value = '/'; break;
                case 'n': value = '\n'; break;
                case 'r': value = '\r'; break;
                case 't': value = '\t'; break;
                default: break;
                }
            }
            output.push_back(value);
        }
        return;
    }
}

Json Json::parse(std::string_view text) { return Parser(text).parse_document(); }
Json Json::ordered_object(Object value, std::vector<std::string> member_order) {
    Json result{std::move(value)};
    result.object_member_order_ = std::move(member_order);
    return result;
}
std::string Json::dump() const { std::ostringstream output; dump_value(output, *this); return output.str(); }
bool Json::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(value_); }
bool Json::is_bool() const noexcept { return std::holds_alternative<bool>(value_); }
bool Json::is_number() const noexcept { return std::holds_alternative<double>(value_); }
bool Json::is_string() const noexcept { return std::holds_alternative<std::string>(value_); }
bool Json::is_object() const noexcept { return std::holds_alternative<Object>(value_); }
bool Json::is_array() const noexcept { return std::holds_alternative<Array>(value_); }
bool Json::as_bool() const { return std::get<bool>(value_); }
double Json::as_number() const { return std::get<double>(value_); }
const std::string& Json::as_string() const { return std::get<std::string>(value_); }
const Json::Object& Json::as_object() const { return std::get<Object>(value_); }
Json::Object& Json::as_object() { return std::get<Object>(value_); }
const Json::Array& Json::as_array() const { return std::get<Array>(value_); }
const std::vector<std::string>& Json::object_member_order() const noexcept {
    return object_member_order_;
}

const Json* Json::find(std::string_view key) const noexcept {
    if (!is_object()) return nullptr;
    const auto it = as_object().find(key);
    return it == as_object().end() ? nullptr : &it->second;
}

std::string Json::string_or(std::string_view key, std::string fallback) const {
    const Json* value = find(key);
    return value && value->is_string() ? value->as_string() : std::move(fallback);
}

bool Json::bool_or(std::string_view key, bool fallback) const {
    const Json* value = find(key);
    return value && value->is_bool() ? value->as_bool() : fallback;
}

}
