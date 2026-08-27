#include "makima/application/catalog.hpp"
#include "makima/application/protocol.hpp"

#include <algorithm>
#include <limits>
#include <optional>
#include <set>
#include <tuple>

namespace makima::application {
namespace {

std::uint64_t read_integer(std::span<const std::uint8_t> data, std::size_t offset, std::size_t width) {
    if (offset + width > data.size()) throw ApplicationError("truncated binary catalog integer");
    std::uint64_t result = 0;
    for (std::size_t index = 0; index < width; ++index)
        result |= static_cast<std::uint64_t>(data[offset + index]) << (index * 8);
    return result;
}

std::vector<std::string> split_branches(std::string value) {
    if (value.empty()) return {};
    try {
        Json parsed = Json::parse(value);
        if (parsed.is_array()) {
            std::vector<std::string> result;
            for (const auto& item : parsed.as_array())
                if (item.is_string() && !item.as_string().empty()) result.push_back(item.as_string());
            return result;
        }
    } catch (const std::exception&) {}
    for (const char separator : {',', '|', ';'}) {
        if (value.find(separator) != std::string::npos) {
            std::vector<std::string> result;
            std::size_t start = 0;
            for (;;) {
                const auto end = value.find(separator, start);
                std::string part = value.substr(start, end - start);
                const auto first = part.find_first_not_of(" \t\r\n");
                const auto last = part.find_last_not_of(" \t\r\n");
                if (first != std::string::npos) result.push_back(part.substr(first, last - first + 1));
                if (end == std::string::npos) break;
                start = end + 1;
            }
            return result;
        }
    }
    return {std::move(value)};
}

std::string subscription_status(std::string_view value) {
    if (value == "active") return "active";
    if (value == "paused") return "paused";
    return "expired";
}

std::string detection_status(std::string_view value) {
    if (value == "updating") return "updating";
    if (value == "detected") return "detected";
    return "undetected";
}

std::string read_wire_text(
    std::span<const std::uint8_t> payload,
    std::size_t& offset,
    std::size_t maximum_length = 4096) {
    if (offset + 2 > payload.size()) {
        throw ApplicationError("truncated login string length");
    }
    const auto length = static_cast<std::size_t>(read_integer(payload, offset, 2));
    offset += 2;
    if (length > maximum_length || length > payload.size() - offset) {
        throw ApplicationError("invalid login string length");
    }
    std::string result(payload.begin() + offset, payload.begin() + offset + length);
    offset += length;
    return result;
}

void collect_subscriptions(const Json& value, std::vector<Subscription>& output) {
    if (value.is_array()) {
        for (const auto& item : value.as_array()) collect_subscriptions(item, output);
        return;
    }
    if (!value.is_object()) return;
    if (const Json* slug = value.find("slug"); slug && slug->is_string() && !slug->as_string().empty()) {
        Subscription item;
        item.name = value.string_or("name");
        item.slug = slug->as_string();
        item.image = value.string_or("image");
        item.description = value.string_or("description");
        item.plan = value.string_or("plan");
        item.status = subscription_status(value.string_or("status"));
        item.expires_at = value.string_or("expires_at");
        item.detection = detection_status(value.string_or("detection"));
        if (const Json* branches = value.find("branches")) {
            if (branches->is_array()) {
                for (const auto& branch : branches->as_array())
                    if (branch.is_string()) item.branches.push_back(branch.as_string());
            } else if (branches->is_string()) item.branches = split_branches(branches->as_string());
        }
        output.push_back(std::move(item));
    }
    for (const auto& [_, nested] : value.as_object()) collect_subscriptions(nested, output);
}

const Json* locate_user(const Json& value) {
    if (value.is_array()) {
        for (const auto& item : value.as_array())
            if (const auto* found = locate_user(item)) return found;
        return nullptr;
    }
    if (!value.is_object()) return nullptr;
    for (const auto key : {"user", "profile", "account"}) {
        if (const auto* nested = value.find(key); nested && nested->is_object()) {
            if (nested->find("name") || nested->find("email") || nested->find("discord_avatar"))
                return nested;
        }
    }
    if ((value.find("name") && value.find("email")) || value.find("discord_avatar"))
        return &value;
    for (const auto& [_, nested] : value.as_object())
        if (const auto* found = locate_user(nested)) return found;
    return nullptr;
}

const Json* locate_changelogs(const Json& value, std::string_view slug) {
    if (value.is_array()) {
        for (const auto& item : value.as_array())
            if (const auto* found = locate_changelogs(item, slug)) return found;
        return nullptr;
    }
    if (!value.is_object()) return nullptr;
    const bool matching_product = slug.empty() || value.string_or("slug") == slug;
    if (matching_product) {
        if (const auto* entries = value.find("changelogs"); entries && entries->is_array())
            return entries;
    }
    if (const auto* changelogs = value.find("changelogs"); changelogs && changelogs->is_object()) {
        if (const auto* entries = changelogs->find(slug); entries && entries->is_array())
            return entries;
    }
    for (const auto& [_, nested] : value.as_object())
        if (const auto* found = locate_changelogs(nested, slug)) return found;
    return nullptr;
}

}

LoginModel parse_login_payload(std::span<const std::uint8_t> payload) {
    if (payload.empty()) throw ApplicationError("login returned an empty payload");


    if (payload[0] != 0) {
        std::size_t error_offset = 1;
        const auto message = read_wire_text(payload, error_offset, 512);
        throw ApplicationError(message.empty() ? "login was rejected" : message);
    }
    if (payload.size() < 17) {
        throw ApplicationError("login success payload is shorter than 17 bytes");
    }

    LoginModel result;
    result.user_id = read_integer(payload, 1, 8);
    result.session_expires_at = read_integer(payload, 9, 8);

    std::size_t offset = 17;
    result.bearer_token = read_wire_text(payload, offset, 511);
    result.account_name = read_wire_text(payload, offset, 127);
    result.profile_payload = read_wire_text(payload, offset, 4096);
    result.subscription_payload = read_wire_text(payload, offset, 511);
    result.control_refresh_token = read_wire_text(payload, offset, 31);
    result.control_ticket = read_wire_text(payload, offset, 79);

    for (const auto* text : {
             &result.account_name,
             &result.profile_payload,
             &result.subscription_payload}) {
        if (text->empty()) continue;
        try {
            result.fields.push_back(Json::parse(*text));
        } catch (const std::exception&) {
            result.fields.emplace_back(*text);
        }
    }

    if (offset + 2 > payload.size()) {
        throw ApplicationError("login subscription count is missing");
    }
    const auto subscription_count = static_cast<std::size_t>(read_integer(payload, offset, 2));
    offset += 2;
    if (subscription_count > 8) {
        throw ApplicationError("login subscription count exceeds the protocol limit");
    }
    result.subscriptions.reserve(subscription_count);
    for (std::size_t index = 0; index < subscription_count; ++index) {
        Subscription subscription;
        subscription.name = read_wire_text(payload, offset, 63);
        subscription.slug = read_wire_text(payload, offset, 63);
        subscription.image = read_wire_text(payload, offset);
        subscription.description = read_wire_text(payload, offset);
        subscription.plan = read_wire_text(payload, offset);
        subscription.status = subscription_status(read_wire_text(payload, offset));
        subscription.expires_at = read_wire_text(payload, offset);
        subscription.detection = detection_status(read_wire_text(payload, offset));
        result.subscriptions.push_back(std::move(subscription));
    }
    if (offset != payload.size()) {
        throw ApplicationError("login response contains trailing bytes");
    }

    for (const auto& field : result.fields) collect_subscriptions(field, result.subscriptions);
    std::set<std::string> seen;
    std::erase_if(result.subscriptions, [&](const Subscription& item) { return !seen.insert(item.slug).second; });
    return result;
}

std::optional<Json> find_user_profile(const LoginModel& model) {
    for (const auto& field : model.fields)
        if (const auto* user = locate_user(field)) return *user;
    if (model.user_id != 0) {
        return Json::Object{
            {"id", static_cast<double>(model.user_id)},
            {"name", "user"},
            {"email", ""},
        };
    }
    return std::nullopt;
}

std::optional<Json> find_product_changelogs(
    const LoginModel& model,
    std::string_view slug) {
    for (const auto& field : model.fields)
        if (const auto* entries = locate_changelogs(field, slug)) return *entries;
    return std::nullopt;
}

std::vector<ChangelogEntry> parse_changelogs(const Json& value) {
    if (!value.is_array()) throw ApplicationError("changelog response is not an array");
    std::vector<ChangelogEntry> result;
    for (const auto& item : value.as_array()) {
        if (!item.is_object()) continue;
        result.push_back({item.string_or("type", "info"), item.string_or("title"),
            item.string_or("message"), item.string_or("body"), item.string_or("publisher", "Makima"),
            item.string_or("created_at"), item.bool_or("is_resolved")});
    }
    return result;
}

Json to_json(const UserProfile& value) {
    return Json::Object{{"id", static_cast<double>(value.id)}, {"name", value.name},
        {"email", value.email}, {"avatar", value.avatar}};
}

Json to_json(const Subscription& value) {
    Json::Array branches;
    for (const auto& branch : value.branches) branches.emplace_back(branch);
    return Json::Object{{"name", value.name}, {"slug", value.slug}, {"image", value.image},
        {"description", value.description}, {"plan", value.plan},
        {"status", value.status}, {"expires_at", value.expires_at},
        {"detection", value.detection}, {"branches", std::move(branches)}};
}

Json to_json(const ChangelogEntry& value) {
    return Json::Object{{"type", value.type}, {"title", value.title}, {"message", value.message},
        {"body", value.body}, {"publisher", value.publisher}, {"created_at", value.created_at},
        {"is_resolved", value.is_resolved}};
}

}
