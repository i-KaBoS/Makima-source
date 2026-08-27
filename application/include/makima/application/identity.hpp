#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace makima::application {

class IHardwareIdentity {
public:
    virtual ~IHardwareIdentity() = default;
    virtual std::string current_user_sid() const = 0;
};

class WindowsHardwareIdentity final : public IHardwareIdentity {
public:
    std::string current_user_sid() const override;
};

std::string resolve_hwid(const IHardwareIdentity& identity) noexcept;
std::string format_protocol_identifier(
    const std::array<std::uint8_t, 16>& identifier,
    std::uint32_t suffix);

}

namespace makima::network::session {

[[nodiscard]] bool write_current_user_sid_utf8(char* destination, int capacity) noexcept;

}
