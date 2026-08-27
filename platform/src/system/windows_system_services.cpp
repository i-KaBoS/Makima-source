#include "makima/platform/system_services.hpp"

#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <dxgi1_2.h>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

extern "C" LONG WINAPI D3DKMTOpenAdapterFromLuid(void*);
extern "C" LONG WINAPI D3DKMTQueryAdapterInfo(const void*);
extern "C" LONG WINAPI D3DKMTCloseAdapter(const void*);

namespace makima::platform {
namespace {




struct OpenAdapterFromLuid {
    LUID adapter_luid{};
    std::uint32_t adapter{};
};

struct QueryAdapterInfo {
    std::uint32_t adapter{};
    std::uint32_t type{};
    void* data{};
    std::uint32_t size{};
};

struct CloseAdapter {
    std::uint32_t adapter{};
};

constexpr std::uint32_t query_wddm_2_7_capabilities = 0x46;
constexpr GUID dxgi_factory1_iid{
    0x770aae78, 0xf26f, 0x4dba,
    {0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}};

class NativeHandle final {
public:
    explicit NativeHandle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~NativeHandle() {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }
    NativeHandle(const NativeHandle&) = delete;
    NativeHandle& operator=(const NativeHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE value_{};
};

class LoadedLibrary final {
public:
    explicit LoadedLibrary(const wchar_t* name) noexcept : value_(LoadLibraryW(name)) {}
    ~LoadedLibrary() {
        if (value_ != nullptr) {
            FreeLibrary(value_);
        }
    }
    LoadedLibrary(const LoadedLibrary&) = delete;
    LoadedLibrary& operator=(const LoadedLibrary&) = delete;
    [[nodiscard]] HMODULE get() const noexcept { return value_; }

private:
    HMODULE value_{};
};

std::array<int, 4> cpuid(int leaf) noexcept {
    std::array<int, 4> result{};
#if defined(_MSC_VER)
    __cpuid(result.data(), leaf);
#else
    unsigned int a = 0;
    unsigned int b = 0;
    unsigned int c = 0;
    unsigned int d = 0;
    __cpuid_count(static_cast<unsigned int>(leaf), 0, a, b, c, d);
    result = {
        static_cast<int>(a),
        static_cast<int>(b),
        static_cast<int>(c),
        static_cast<int>(d),
    };
#endif
    return result;
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string wide_to_utf8(std::wstring_view value) {
    if (value.empty()) {
        return {};
    }
    const auto count = WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);
    if (count <= 0) {
        return {};
    }
    std::string result(static_cast<std::size_t>(count), '\0');
    WideCharToMultiByte(
        CP_UTF8,
        0,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        count,
        nullptr,
        nullptr);
    return result;
}

std::optional<std::string> registry_string(
    HKEY root,
    const wchar_t* key_path,
    const wchar_t* value_name) {
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegGetValueW(
            root,
            key_path,
            value_name,
            RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ,
            &type,
            nullptr,
            &bytes) != ERROR_SUCCESS ||
        bytes < sizeof(wchar_t)) {
        return std::nullopt;
    }
    std::vector<wchar_t> value(bytes / sizeof(wchar_t) + 1, L'\0');
    if (RegGetValueW(
            root,
            key_path,
            value_name,
            RRF_RT_REG_SZ | RRF_RT_REG_MULTI_SZ,
            &type,
            value.data(),
            &bytes) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    return wide_to_utf8(value.data());
}

bool contains_virtualization_vendor(std::string_view text) {
    const auto lower = lowercase(std::string{text});
    constexpr std::array vendors{
        "virtualbox", "vbox", "vmware", "qemu", "kvm", "xen",
        "parallels", "hyper-v", "microsoft corporation virtual",
    };
    return std::ranges::any_of(vendors, [&](std::string_view vendor) {
        return lower.find(vendor) != std::string::npos;
    });
}

std::uint16_t native_machine_fallback() noexcept {
    SYSTEM_INFO information{};
    GetNativeSystemInfo(&information);
    switch (information.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return IMAGE_FILE_MACHINE_AMD64;
    case PROCESSOR_ARCHITECTURE_ARM64:
        return IMAGE_FILE_MACHINE_ARM64;
    case PROCESSOR_ARCHITECTURE_INTEL:
        return IMAGE_FILE_MACHINE_I386;
    default:
        return IMAGE_FILE_MACHINE_UNKNOWN;
    }
}

[[nodiscard]] GraphicsSchedulingCapabilities query_graphics_scheduling(
    const DXGI_ADAPTER_DESC1& description) {
    GraphicsSchedulingCapabilities result;
    result.adapter = wide_to_utf8(description.Description);

    OpenAdapterFromLuid open{description.AdapterLuid};
    if (D3DKMTOpenAdapterFromLuid(&open) < 0) {
        return result;
    }

    std::uint32_t capabilities = 0;
    const QueryAdapterInfo query{
        open.adapter,
        query_wddm_2_7_capabilities,
        &capabilities,
        sizeof(capabilities),
    };
    const auto query_status = D3DKMTQueryAdapterInfo(&query);
    const CloseAdapter close{open.adapter};
    D3DKMTCloseAdapter(&close);
    if (query_status < 0) {
        return result;
    }

    result.query_succeeded = true;
    result.hardware_scheduling_supported = (capabilities & (1U << 0U)) != 0;
    result.hardware_scheduling_enabled = (capabilities & (1U << 1U)) != 0;
    result.hardware_scheduling_enabled_by_default = (capabilities & (1U << 2U)) != 0;
    result.independent_vsync_control = (capabilities & (1U << 3U)) != 0;
    return result;
}

[[nodiscard]] std::vector<GraphicsSchedulingCapabilities> query_graphics_adapters() {
    using CreateDxgiFactory1 = HRESULT(WINAPI*)(REFIID, void**);
    LoadedLibrary dxgi{L"dxgi.dll"};
    if (dxgi.get() == nullptr) {
        return {};
    }
    const auto procedure = GetProcAddress(dxgi.get(), "CreateDXGIFactory1");
    CreateDxgiFactory1 create_factory = nullptr;
    static_assert(sizeof(create_factory) == sizeof(procedure));
    std::memcpy(&create_factory, &procedure, sizeof(create_factory));
    if (create_factory == nullptr) {
        return {};
    }

    IDXGIFactory1* factory = nullptr;
    if (FAILED(create_factory(dxgi_factory1_iid, reinterpret_cast<void**>(&factory))) ||
        factory == nullptr) {
        return {};
    }

    std::vector<GraphicsSchedulingCapabilities> result;
    for (UINT index = 0;; ++index) {
        IDXGIAdapter1* adapter = nullptr;
        const auto status = factory->EnumAdapters1(index, &adapter);
        if (status == DXGI_ERROR_NOT_FOUND) {
            break;
        }
        if (FAILED(status) || adapter == nullptr) {
            continue;
        }
        DXGI_ADAPTER_DESC1 description{};
        if (SUCCEEDED(adapter->GetDesc1(&description))) {
            result.push_back(query_graphics_scheduling(description));
        }
        adapter->Release();
    }
    factory->Release();
    return result;
}

}

PrivilegeResult TokenPrivilegeManager::enable(std::wstring_view privilege_name) const {
    if (privilege_name.empty()) {
        return {false, false, "privilege name cannot be empty"};
    }
    HANDLE raw_token = nullptr;
    if (OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &raw_token) == FALSE) {
        return {false, false, "OpenProcessToken failed"};
    }
    NativeHandle token{raw_token};
    std::wstring name(privilege_name);
    LUID identifier{};
    if (LookupPrivilegeValueW(nullptr, name.c_str(), &identifier) == FALSE) {
        return {false, false, "LookupPrivilegeValueW failed"};
    }
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = identifier;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    if (AdjustTokenPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr) == FALSE) {
        return {false, false, "AdjustTokenPrivileges failed"};
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        return {true, false, "the token does not contain the requested privilege"};
    }
    return {true, true, {}};
}

bool TokenPrivilegeManager::current_process_is_elevated() const {
    HANDLE raw_token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token) == FALSE) {
        return false;
    }
    NativeHandle token{raw_token};
    TOKEN_ELEVATION elevation{};
    DWORD written = 0;
    return GetTokenInformation(
               token.get(),
               TokenElevation,
               &elevation,
               sizeof(elevation),
               &written) != FALSE &&
           elevation.TokenIsElevated != 0;
}

EnvironmentReport WindowsEnvironmentInspector::inspect() const {
    EnvironmentReport report;
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory) != FALSE) {
        report.physical_memory_bytes = memory.ullTotalPhys;
    }
    report.debugger_present = IsDebuggerPresent() != FALSE;
    report.remote_session = GetSystemMetrics(SM_REMOTESESSION) != 0;

    using IsWow64Process2Function = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    const auto kernel = GetModuleHandleW(L"kernel32.dll");
    const auto procedure = GetProcAddress(kernel, "IsWow64Process2");
    IsWow64Process2Function is_wow64_process2 = nullptr;
    static_assert(sizeof(is_wow64_process2) == sizeof(procedure));
    std::memcpy(&is_wow64_process2, &procedure, sizeof(is_wow64_process2));
    if (is_wow64_process2 != nullptr) {
        is_wow64_process2(
            GetCurrentProcess(),
            &report.process_machine,
            &report.native_machine);
    } else {
        report.native_machine = native_machine_fallback();
        report.process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    }

    const auto processor = cpuid(1);
    report.hypervisor_present = (static_cast<std::uint32_t>(processor[2]) & (1U << 31U)) != 0;
    if (report.hypervisor_present) {
        const auto hypervisor = cpuid(0x40000000);
        std::array<char, 13> vendor{};
        std::memcpy(vendor.data(), &hypervisor[1], 4);
        std::memcpy(vendor.data() + 4, &hypervisor[2], 4);
        std::memcpy(vendor.data() + 8, &hypervisor[3], 4);
        report.virtualization_indicators.emplace_back("cpuid:", 6);
        report.virtualization_indicators.back().append(vendor.data());
    }

    constexpr std::array registry_values{
        L"SystemManufacturer",
        L"SystemProductName",
        L"BIOSVendor",
        L"BaseBoardManufacturer",
    };
    for (const auto* value_name : registry_values) {
        const auto value = registry_string(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\BIOS",
            value_name);
        if (value && contains_virtualization_vendor(*value)) {
            report.virtualization_indicators.push_back(
                "firmware:" + wide_to_utf8(value_name) + "=" + *value);
        }
    }
    report.graphics_scheduling = query_graphics_adapters();
    return report;
}

bool WindowsEnvironmentInspector::has_active_network_adapter() const {
    ULONG bytes = 16 * 1024;
    std::vector<std::byte> storage(bytes);
    ULONG result = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
        nullptr,
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),
        &bytes);
    if (result == ERROR_BUFFER_OVERFLOW) {
        storage.resize(bytes);
        result = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
            nullptr,
            reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data()),
            &bytes);
    }
    if (result != NO_ERROR) {
        return false;
    }
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
         adapter != nullptr;
         adapter = adapter->Next) {
        if (adapter->OperStatus == IfOperStatusUp &&
            adapter->IfType != IF_TYPE_SOFTWARE_LOOPBACK &&
            adapter->IfType != IF_TYPE_TUNNEL) {
            return true;
        }
    }
    return false;
}

application::Json WindowsSystemService::check_vm() {
    const auto report = inspector_.inspect();
    const bool detected = report.hypervisor_present || !report.virtualization_indicators.empty();
    application::Json::Array indicators;
    for (const auto& indicator : report.virtualization_indicators) {
        indicators.emplace_back(indicator);
    }
    application::Json::Array graphics_scheduling;
    for (const auto& adapter : report.graphics_scheduling) {
        graphics_scheduling.emplace_back(application::Json::Object{
            {"adapter", adapter.adapter},
            {"querySucceeded", adapter.query_succeeded},
            {"hardwareSchedulingSupported", adapter.hardware_scheduling_supported},
            {"hardwareSchedulingEnabled", adapter.hardware_scheduling_enabled},
            {"hardwareSchedulingEnabledByDefault", adapter.hardware_scheduling_enabled_by_default},
            {"independentVsyncControl", adapter.independent_vsync_control},
        });
    }
    return application::Json::Object{
        {"success", true},
        {"detected", detected},
        {"is_vm", detected},
        {"hypervisor", report.hypervisor_present},
        {"remoteSession", report.remote_session},
        {"debugger", report.debugger_present},
        {"indicators", std::move(indicators)},
        {"graphicsScheduling", std::move(graphics_scheduling)},
    };
}

application::Json WindowsSystemService::check_ram() {
    const auto report = inspector_.inspect();
    const bool sufficient = report.physical_memory_bytes >= minimum_memory_bytes_;
    return application::Json::Object{
        {"success", sufficient},
        {"warning", !sufficient},
        {"totalBytes", static_cast<double>(report.physical_memory_bytes)},
        {"total_gb", static_cast<double>(report.physical_memory_bytes) /
                         (1024.0 * 1024.0 * 1024.0)},
        {"minimumBytes", static_cast<double>(minimum_memory_bytes_)},
    };
}

application::Json WindowsSystemService::check_connection() {
    const bool connected = inspector_.has_active_network_adapter();
    return application::Json::Object{
        {"success", connected},
        {"connected", connected},
        {"ok", connected},
        {"error", connected ? "" : "No active network adapter was found."},
    };
}

}
