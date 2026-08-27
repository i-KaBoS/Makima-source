#include "makima/platform/kernel_symbols.hpp"

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace makima::platform {
namespace {

struct ImageView {
    std::vector<std::uint8_t> bytes;
    const IMAGE_NT_HEADERS64* nt{};
    const IMAGE_SECTION_HEADER* sections{};
};

std::optional<ImageView> open_pe(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary | std::ios::ate);
    if (!stream) return std::nullopt;
    const auto length = stream.tellg();
    if (length <= 0 || length > 512LL * 1024 * 1024) return std::nullopt;
    ImageView view;
    view.bytes.resize(static_cast<std::size_t>(length));
    stream.seekg(0);
    stream.read(reinterpret_cast<char*>(view.bytes.data()), length);
    if (!stream || view.bytes.size() < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(view.bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > view.bytes.size()) {
        return std::nullopt;
    }
    view.nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(view.bytes.data() + dos->e_lfanew);
    if (view.nt->Signature != IMAGE_NT_SIGNATURE ||
        view.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::nullopt;
    }
    view.sections = IMAGE_FIRST_SECTION(view.nt);
    const auto section_end = reinterpret_cast<const std::uint8_t*>(
        view.sections + view.nt->FileHeader.NumberOfSections);
    if (section_end > view.bytes.data() + view.bytes.size()) return std::nullopt;
    return view;
}

std::optional<std::size_t> rva_to_file_offset(const ImageView& view, std::uint32_t rva) {
    if (rva < view.nt->OptionalHeader.SizeOfHeaders && rva < view.bytes.size()) return rva;
    for (std::uint16_t index = 0; index < view.nt->FileHeader.NumberOfSections; ++index) {
        const auto& section = view.sections[index];
        const auto extent = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva >= section.VirtualAddress && rva - section.VirtualAddress < extent) {
            const auto offset = static_cast<std::uint64_t>(section.PointerToRawData) +
                                (rva - section.VirtualAddress);
            if (offset < view.bytes.size()) return static_cast<std::size_t>(offset);
        }
    }
    return std::nullopt;
}

std::string basename(std::string value) {
    const auto separator = value.find_last_of("/\\");
    return separator == std::string::npos ? value : value.substr(separator + 1);
}

std::uintptr_t loaded_kernel_base() {
    std::array<void*, 1024> drivers{};
    DWORD required = 0;
    if (EnumDeviceDrivers(drivers.data(), sizeof(drivers), &required) == FALSE || required == 0) {
        return 0;
    }
    return reinterpret_cast<std::uintptr_t>(drivers[0]);
}

std::filesystem::path installed_kernel_path() {
    std::array<wchar_t, MAX_PATH> directory{};
    const auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (length == 0 || length >= directory.size()) return {};
    return std::filesystem::path{std::wstring_view{directory.data(), length}} / L"ntoskrnl.exe";
}

}

std::optional<CodeViewIdentity> read_codeview_identity(
    const std::filesystem::path& image_path) {
    auto view = open_pe(image_path);
    if (!view) return std::nullopt;
    const auto directory =
        view->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
    const auto directory_offset = rva_to_file_offset(*view, directory.VirtualAddress);
    if (!directory_offset || directory.Size < sizeof(IMAGE_DEBUG_DIRECTORY) ||
        *directory_offset + directory.Size > view->bytes.size()) {
        return std::nullopt;
    }
    const auto count = directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
    const auto* entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY*>(
        view->bytes.data() + *directory_offset);
    for (std::size_t index = 0; index < count; ++index) {
        const auto& entry = entries[index];
        if (entry.Type != IMAGE_DEBUG_TYPE_CODEVIEW || entry.SizeOfData < 25 ||
            static_cast<std::uint64_t>(entry.PointerToRawData) + entry.SizeOfData >
                view->bytes.size()) {
            continue;
        }
        const auto* data = view->bytes.data() + entry.PointerToRawData;
        if (std::memcmp(data, "RSDS", 4) != 0) continue;
        CodeViewIdentity identity;
        std::copy_n(data + 4, identity.guid.size(), identity.guid.begin());
        std::memcpy(&identity.age, data + 20, sizeof(identity.age));
        const auto* name = reinterpret_cast<const char*>(data + 24);
        const auto capacity = entry.SizeOfData - 24;
        const auto length = std::find(name, name + capacity, '\0') - name;
        identity.pdb_name = basename(std::string(name, length));
        if (!identity.pdb_name.empty()) return identity;
    }
    return std::nullopt;
}

std::optional<KernelImageIdentity> inspect_running_kernel() {
    const auto image = installed_kernel_path();
    auto view = open_pe(image);
    const auto codeview = read_codeview_identity(image);
    const auto live_base = loaded_kernel_base();
    if (!view || !codeview || live_base == 0) return std::nullopt;
    return KernelImageIdentity{
        .installed_image = image,
        .loaded_base = live_base,
        .preferred_base = view->nt->OptionalHeader.ImageBase,
        .codeview = std::move(*codeview),
    };
}

std::string microsoft_symbol_url(const CodeViewIdentity& identity) {
    if (identity.pdb_name.empty()) return {};
    const auto* guid = identity.guid.data();
    std::ostringstream key;
    key << std::uppercase << std::hex << std::setfill('0')
        << std::setw(2) << static_cast<unsigned>(guid[3])
        << std::setw(2) << static_cast<unsigned>(guid[2])
        << std::setw(2) << static_cast<unsigned>(guid[1])
        << std::setw(2) << static_cast<unsigned>(guid[0])
        << std::setw(2) << static_cast<unsigned>(guid[5])
        << std::setw(2) << static_cast<unsigned>(guid[4])
        << std::setw(2) << static_cast<unsigned>(guid[7])
        << std::setw(2) << static_cast<unsigned>(guid[6]);
    for (std::size_t index = 8; index < identity.guid.size(); ++index) {
        key << std::setw(2) << static_cast<unsigned>(guid[index]);
    }
    key << identity.age;
    return "https://msdl.microsoft.com/download/symbols/" + identity.pdb_name +
           "/" + key.str() + "/" + identity.pdb_name;
}

struct KernelSymbolResolver::State {
    HANDLE process{GetCurrentProcess()};
    bool initialized{};
    DWORD64 module_base{};
    std::optional<KernelImageIdentity> kernel;

    ~State() {
        if (initialized) SymCleanup(process);
    }
};

KernelSymbolResolver::KernelSymbolResolver(std::filesystem::path symbol_cache)
    : state_(std::make_unique<State>()) {
    if (symbol_cache.empty()) symbol_cache = std::filesystem::temp_directory_path() / L"MakimaSymbols";
    std::error_code error;
    std::filesystem::create_directories(symbol_cache, error);
    const std::wstring search_path =
        L"srv*" + symbol_cache.wstring() + L"*https://msdl.microsoft.com/download/symbols";
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_UNDNAME | SYMOPT_LOAD_LINES);
    state_->initialized = SymInitializeW(state_->process, search_path.c_str(), FALSE) != FALSE;
}

KernelSymbolResolver::~KernelSymbolResolver() = default;
KernelSymbolResolver::KernelSymbolResolver(KernelSymbolResolver&&) noexcept = default;
KernelSymbolResolver& KernelSymbolResolver::operator=(KernelSymbolResolver&&) noexcept = default;

bool KernelSymbolResolver::load_running_kernel() {
    if (!state_->initialized) return false;
    state_->kernel = inspect_running_kernel();
    if (!state_->kernel) return false;
    state_->module_base = SymLoadModuleExW(
        state_->process,
        nullptr,
        state_->kernel->installed_image.c_str(),
        L"nt",
        static_cast<DWORD64>(state_->kernel->loaded_base),
        0,
        nullptr,
        0);
    return state_->module_base != 0;
}

std::optional<std::uintptr_t> KernelSymbolResolver::resolve(
    std::string_view symbol_name) const {
    if (!state_->initialized || state_->module_base == 0 || symbol_name.empty()) return std::nullopt;
    std::array<std::byte, sizeof(SYMBOL_INFO) + MAX_SYM_NAME> storage{};
    auto* information = reinterpret_cast<SYMBOL_INFO*>(storage.data());
    information->SizeOfStruct = sizeof(SYMBOL_INFO);
    information->MaxNameLen = MAX_SYM_NAME;
    const std::string qualified = "nt!" + std::string(symbol_name);
    if (SymFromName(state_->process, qualified.c_str(), information) == FALSE) return std::nullopt;
    return static_cast<std::uintptr_t>(information->Address);
}

const std::optional<KernelImageIdentity>& KernelSymbolResolver::identity() const noexcept {
    return state_->kernel;
}

}
