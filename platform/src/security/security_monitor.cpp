#include "makima/platform/security_monitor.hpp"

#include "makima/application/common.hpp"
#include "telemetry/reporting/reporting.hpp"

#include <windows.h>
#include <dwmapi.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

namespace makima::platform {
namespace {

std::string utf8(std::wstring_view value) {
    std::array<char, 0x104> result{};
    if (value.empty()) {
        return {};
    }
    WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
        result.data(), 0x103, nullptr, nullptr);
    return result.data();
}

std::string normalized(std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

char* protected_format_unsigned(
    char* destination,
    std::size_t capacity,
    const char* format,
    std::uint64_t value) noexcept {
    if (destination == nullptr || capacity == 0 || format == nullptr) {
        return nullptr;
    }

    int written = -1;
    if (std::strcmp(format, "%llu") == 0) {
        written = std::snprintf(
            destination, capacity, "%llu", static_cast<unsigned long long>(value));
    } else if (std::strcmp(format, "%lu") == 0) {
        written = std::snprintf(
            destination, capacity, "%lu", static_cast<unsigned long>(value));
    }
    if (written < 0 || static_cast<std::size_t>(written) >= capacity) {
        destination[0] = '\0';
        return nullptr;
    }
    return destination;
}

}

std::string format_process_record_json(const ProcessRecord& process) {
    char process_id[0x18]{};
    char thread_count[0x10]{};
    if (protected_format_unsigned(
            process_id, sizeof(process_id), "%llu", process.process_id) == nullptr ||
        protected_format_unsigned(
            thread_count, sizeof(thread_count), "%lu", process.thread_count) == nullptr) {
        return {};
    }

    std::string result{"{\"pid\":"};
    result.append(process_id);
    result.append(",\"name\":");
    ::makima::telemetry::reporting::append_telemetry_json_escaped_text(
        &result, process.image_name.c_str(), process.image_name.size());
    result.append(",\"threads\":");
    result.append(thread_count);
    result.push_back('}');
    return result;
}



std::vector<ProcessRecord> ProcessInventory::snapshot() const {
    constexpr NTSTATUS status_info_length_mismatch =
        static_cast<NTSTATUS>(0xC0000004UL);
    constexpr unsigned maximum_query_attempts = 6;
    constexpr std::size_t maximum_processes = 4096;

    std::vector<std::byte> buffer;
    ULONG query_size = 0x10000;
    NTSTATUS status = status_info_length_mismatch;
    for (unsigned attempt = 0;
         attempt < maximum_query_attempts && status == status_info_length_mismatch;
         ++attempt) {
        buffer.resize(query_size);
        ULONG required_size{};
        status = NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.data(),
            query_size,
            &required_size);
        if (status == status_info_length_mismatch) {
            query_size <<= 1U;
        }
    }
    if (status != 0) {
        return {};
    }

    std::vector<ProcessRecord> result;
    auto* entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(buffer.data());
    for (std::size_t count = 0; count < maximum_processes; ++count) {
        const auto process_id = static_cast<std::uint64_t>(
            reinterpret_cast<std::uintptr_t>(entry->UniqueProcessId));
        std::string image_name;
        if (entry->ImageName.Buffer != nullptr && entry->ImageName.Length != 0) {
            image_name = utf8(std::wstring_view{
                entry->ImageName.Buffer,
                entry->ImageName.Length / sizeof(wchar_t)});
        } else {
            image_name = process_id == 0 ? "Idle" : "System";
        }
        result.push_back({
            .process_id = process_id,
            .parent_process_id = static_cast<std::uint32_t>(
                reinterpret_cast<std::uintptr_t>(entry->InheritedFromUniqueProcessId)),
            .thread_count = entry->NumberOfThreads,
            .image_name = std::move(image_name),
        });
        if (entry->NextEntryOffset == 0) {
            break;
        }
        entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<const std::byte*>(entry) + entry->NextEntryOffset);
    }
    return result;
}

std::optional<BlockedProcessFinding> ProcessInventory::find_first(
    std::span<const std::string_view> blocked_names) const {
    std::vector<std::string> normalized_names;
    normalized_names.reserve(blocked_names.size());
    for (const auto name : blocked_names) {
        if (!name.empty()) normalized_names.push_back(normalized(name));
    }
    for (const auto& process : snapshot()) {
        const auto image = normalized(process.image_name);
        const auto match = std::ranges::find(normalized_names, image);
        if (match != normalized_names.end()) return BlockedProcessFinding{process, *match};
    }
    return std::nullopt;
}

DesktopTimingReport query_desktop_timing() {
    DesktopTimingReport result;
    BOOL enabled = FALSE;
    result.composition_enabled =
        SUCCEEDED(DwmIsCompositionEnabled(&enabled)) && enabled != FALSE;
    DWM_TIMING_INFO timing{};
    timing.cbSize = sizeof(timing);
    if (SUCCEEDED(DwmGetCompositionTimingInfo(nullptr, &timing))) {
        result.refresh_counter = timing.cRefresh;
        result.qpc_refresh_period = timing.qpcRefreshPeriod;
        result.qpc_vblank = timing.qpcVBlank;
    }
    return result;
}

}
