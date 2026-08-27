#pragma once

#include "process/pe_mapping/pe_mapping.hpp"

#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace makima::process::pe_mapping {

class MappingTextCache final {
public:
    template <typename Provider>
    [[nodiscard]] const std::string& narrow(
        VirtualAddress initialization_guard,
        Provider&& provider) {
        std::scoped_lock lock{mutex_};
        auto [found, inserted] = narrow_.try_emplace(initialization_guard);
        if (inserted) {
            found->second = std::forward<Provider>(provider)();
        }
        return found->second;
    }

    template <typename Provider>
    [[nodiscard]] const std::wstring& wide(
        VirtualAddress initialization_guard,
        Provider&& provider) {
        std::scoped_lock lock{mutex_};
        auto [found, inserted] = wide_.try_emplace(initialization_guard);
        if (inserted) {
            found->second = std::forward<Provider>(provider)();
        }
        return found->second;
    }



    void abort_initialization(VirtualAddress initialization_guard) noexcept {
        std::scoped_lock lock{mutex_};
        narrow_.erase(initialization_guard);
        wide_.erase(initialization_guard);
    }

private:
    std::mutex mutex_;
    std::unordered_map<VirtualAddress, std::string> narrow_;
    std::unordered_map<VirtualAddress, std::wstring> wide_;
};

[[nodiscard]] inline MappingTextCache& mapping_text_cache();

inline MappingTextCache& mapping_text_cache() {
    static MappingTextCache cache;
    return cache;
}

}
