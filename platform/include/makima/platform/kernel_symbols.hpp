#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <memory>
#include <string>
#include <string_view>

namespace makima::platform {

struct CodeViewIdentity {
    std::array<std::uint8_t, 16> guid{};
    std::uint32_t age{};
    std::string pdb_name;
};

struct KernelImageIdentity {
    std::filesystem::path installed_image;
    std::uintptr_t loaded_base{};
    std::uint64_t preferred_base{};
    CodeViewIdentity codeview;
};

[[nodiscard]] std::optional<CodeViewIdentity> read_codeview_identity(
    const std::filesystem::path& image_path);
[[nodiscard]] std::optional<KernelImageIdentity> inspect_running_kernel();
[[nodiscard]] std::string microsoft_symbol_url(const CodeViewIdentity& identity);

class KernelSymbolResolver final {
public:
    explicit KernelSymbolResolver(std::filesystem::path symbol_cache);
    ~KernelSymbolResolver();
    KernelSymbolResolver(KernelSymbolResolver&&) noexcept;
    KernelSymbolResolver& operator=(KernelSymbolResolver&&) noexcept;
    KernelSymbolResolver(const KernelSymbolResolver&) = delete;
    KernelSymbolResolver& operator=(const KernelSymbolResolver&) = delete;

    [[nodiscard]] bool load_running_kernel();
    [[nodiscard]] std::optional<std::uintptr_t> resolve(std::string_view symbol_name) const;
    [[nodiscard]] const std::optional<KernelImageIdentity>& identity() const noexcept;

private:
    struct State;
    std::unique_ptr<State> state_;
};

}
