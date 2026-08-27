#pragma once

#include <map>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace makima::application {




void extract_json_string_member(
    const std::string_view& document,
    const char* member_name,
    std::string& output);

class Json {
public:
    using Object = std::map<std::string, Json, std::less<>>;
    using Array = std::vector<Json>;
    using Value = std::variant<std::nullptr_t, bool, double, std::string, Object, Array>;

    Json() : value_(nullptr) {}
    Json(std::nullptr_t) : value_(nullptr) {}
    Json(bool value) : value_(value) {}
    Json(double value) : value_(value) {}
    Json(int value) : value_(static_cast<double>(value)) {}
    Json(std::string value) : value_(std::move(value)) {}
    Json(const char* value) : value_(std::string(value)) {}
    Json(Object value) : value_(std::move(value)) {}
    Json(Array value) : value_(std::move(value)) {}

    static Json parse(std::string_view text);
    static Json ordered_object(Object value, std::vector<std::string> member_order);
    std::string dump() const;

    bool is_null() const noexcept;
    bool is_bool() const noexcept;
    bool is_number() const noexcept;
    bool is_string() const noexcept;
    bool is_object() const noexcept;
    bool is_array() const noexcept;

    bool as_bool() const;
    double as_number() const;
    const std::string& as_string() const;
    const Object& as_object() const;
    Object& as_object();
    const Array& as_array() const;
    const std::vector<std::string>& object_member_order() const noexcept;

    const Json* find(std::string_view key) const noexcept;
    std::string string_or(std::string_view key, std::string fallback = {}) const;
    bool bool_or(std::string_view key, bool fallback = false) const;

private:
    Value value_;
    std::vector<std::string> object_member_order_;
};

}
