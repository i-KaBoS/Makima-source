#pragma once

#include "makima/application/common.hpp"
#include "makima/application/json.hpp"

#include <cstdint>
#include <optional>

namespace makima::application {

struct UserProfile {
    std::uint64_t id{};
    std::string name;
    std::string email;
    std::string avatar;
};

struct Subscription {
    std::string name;
    std::string slug;
    std::string image;
    std::string description;
    std::string plan;
    std::string status;
    std::string expires_at;
    std::string detection;
    std::vector<std::string> branches;
};

struct ChangelogEntry {
    std::string type;
    std::string title;
    std::string message;
    std::string body;
    std::string publisher;
    std::string created_at;
    bool is_resolved{};
};

struct LoginModel {
    std::uint64_t user_id{};
    std::uint64_t session_expires_at{};
    std::string bearer_token;
    std::string account_name;
    std::string profile_payload;
    std::string subscription_payload;
    std::string control_refresh_token;
    std::string control_ticket;
    std::vector<Json> fields;
    std::vector<Subscription> subscriptions;
};

LoginModel parse_login_payload(std::span<const std::uint8_t> payload);
std::optional<Json> find_user_profile(const LoginModel& model);
std::optional<Json> find_product_changelogs(
    const LoginModel& model,
    std::string_view slug);
std::vector<ChangelogEntry> parse_changelogs(const Json& value);
Json to_json(const UserProfile& value);
Json to_json(const Subscription& value);
Json to_json(const ChangelogEntry& value);

}
