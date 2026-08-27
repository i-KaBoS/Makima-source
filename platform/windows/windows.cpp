#include "platform/windows/windows.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <new>
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

namespace makima::platform::windows {

char* allocate_shcore_ansi_module_name(const std::byte* protected_source) {
    (void)protected_source;
    constexpr char module_name[] = "SHCore.dll";
    auto* output = static_cast<char*>(::operator new(sizeof(module_name)));
    std::memcpy(output, module_name, sizeof(module_name));
    return output;
}

HMODULE load_dynamic_library(std::string_view module_name) {
    if (module_name.empty()) return nullptr;
    std::string owned;
    owned.assign(module_name.data(), module_name.size());
    if (owned.find('\0') != std::string::npos) return nullptr;
    HMODULE module = LoadLibraryA(owned.c_str());
    return module;
}

}
