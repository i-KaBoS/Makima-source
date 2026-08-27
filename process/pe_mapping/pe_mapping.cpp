#include "process/pe_mapping/pe_mapping.hpp"
#include "process/memory/memory.hpp"
#include "process/launch/coordination.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace makima::process::pe_mapping {

namespace {

using makima::process::memory::ProcessMemory;

class UniqueHandle final {
public:
    explicit UniqueHandle(HANDLE value = nullptr) noexcept : value_(value) {}
    ~UniqueHandle() { if (value_ != nullptr) ::CloseHandle(value_); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }
private:
    HANDLE value_{};
};

[[nodiscard]] std::span<const std::uint8_t> checked_file_range(
    std::span<const std::uint8_t> image,
    std::size_t offset,
    std::size_t size) {
    if (offset > image.size() || size > image.size() - offset) {
        throw MappingError("portable executable section exceeds the source image");
    }
    return image.subspan(offset, size);
}

void write_exact(
    const ProcessMemory& memory,
    VirtualAddress destination,
    std::span<const std::uint8_t> source) {
    const auto bytes = std::as_bytes(source);
    if (memory.write(destination, bytes) != bytes.size()) {
        throw MappingError("remote image write was incomplete");
    }
}

DWORD section_protection(makima::platform::SectionAccess access) noexcept {
    using makima::platform::SectionAccess;
    const auto bits = static_cast<std::uint8_t>(access);
    const bool read = (bits & static_cast<std::uint8_t>(SectionAccess::read)) != 0;
    const bool write = (bits & static_cast<std::uint8_t>(SectionAccess::write)) != 0;
    const bool execute = (bits & static_cast<std::uint8_t>(SectionAccess::execute)) != 0;
    if (execute) {
        return write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
    }
    return write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS);
}

std::wstring widen_module_name(std::string_view name) {
    std::wstring result;
    result.reserve(name.size());
    for (const unsigned char character : name) {
        result.push_back(static_cast<wchar_t>(character));
    }
    return result;
}

std::wstring loader_host_module_name(std::string_view import_name) {
    const std::string name{import_name};
    const HMODULE local = ::LoadLibraryExA(
        name.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (local == nullptr) {
        return widen_module_name(import_name);
    }
    std::array<wchar_t, 32768> path{};
    const DWORD length = ::GetModuleFileNameW(local, path.data(), path.size());
    ::FreeLibrary(local);
    if (length == 0 || length >= path.size()) {
        return widen_module_name(import_name);
    }
    std::wstring result{path.data(), length};
    const auto separator = result.find_last_of(L"\\/");
    return separator == std::wstring::npos ? result : result.substr(separator + 1);
}

struct RemoteCallArguments {
    std::uint64_t function{};
    std::uint64_t first{};
    std::uint64_t second{};
    std::uint64_t third{};
};


constexpr std::array<std::uint8_t, 27> remote_three_argument_call_gate{
    0x48, 0x83, 0xEC, 0x28,
    0x48, 0x8B, 0x01,
    0x48, 0x8B, 0x51, 0x10,
    0x4C, 0x8B, 0x41, 0x18,
    0x48, 0x8B, 0x49, 0x08,
    0xFF, 0xD0,
    0x48, 0x83, 0xC4, 0x28,
    0xC3,
};

bool invoke_remote_three_args(
    HANDLE process,
    const ProcessMemory& memory,
    VirtualAddress function,
    VirtualAddress first,
    VirtualAddress second,
    VirtualAddress third,
    bool require_true) {
    const std::size_t allocation_size = 0x1000;
    auto* allocation = static_cast<std::uint8_t*>(::VirtualAllocEx(
        process, nullptr, allocation_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (allocation == nullptr) {
        throw MappingError("failed to allocate remote call gate");
    }
    const VirtualAddress code = reinterpret_cast<VirtualAddress>(allocation);
    const VirtualAddress arguments_address = code + 0x100;
    const RemoteCallArguments arguments{function, first, second, third};
    try {
        write_exact(memory, code, remote_three_argument_call_gate);
        const auto argument_bytes = std::as_bytes(std::span{&arguments, std::size_t{1}});
        if (memory.write(arguments_address, argument_bytes) != argument_bytes.size()) {
            throw MappingError("failed to write remote call arguments");
        }
        DWORD old_protection{};
        if (!::VirtualProtectEx(
                process, allocation, remote_three_argument_call_gate.size(),
                PAGE_EXECUTE_READ, &old_protection)) {
            throw MappingError("failed to protect remote call gate");
        }
        UniqueHandle thread{::CreateRemoteThread(
            process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(code),
            reinterpret_cast<void*>(arguments_address), 0, nullptr)};
        if (!thread || ::WaitForSingleObject(thread.get(), 15000) != WAIT_OBJECT_0) {
            throw MappingError("remote initializer timed out");
        }
        DWORD exit_code{};
        if (!::GetExitCodeThread(thread.get(), &exit_code)) {
            throw MappingError("failed to read remote initializer result");
        }
        ::VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
        return !require_true || exit_code != 0;
    } catch (...) {
        ::VirtualFreeEx(process, allocation, 0, MEM_RELEASE);
        throw;
    }
}

RemoteModule require_remote_module(std::uint32_t process_id, std::string_view module_name) {
    if (auto module = find_remote_module(process_id, widen_module_name(module_name))) {
        return *module;
    }
    throw MappingError("required import DLL is not loaded in the target: " + std::string{module_name});
}

void load_remote_module(
    std::uint32_t process_id,
    HANDLE process,
    const ProcessMemory& memory,
    std::string_view module_name) {
    const auto kernel32 = require_remote_module(process_id, "kernel32.dll");
    const auto load_library = resolve_remote_export(process_id, kernel32, "LoadLibraryA");
    if (load_library == 0) {
        throw MappingError("could not resolve target LoadLibraryA");
    }
    const std::string terminated = std::string{module_name} + '\0';
    void* remote_name = ::VirtualAllocEx(
        process, nullptr, terminated.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_name == nullptr) {
        throw MappingError("failed to allocate target import name");
    }
    try {
        write_exact(
            memory, reinterpret_cast<VirtualAddress>(remote_name),
            {reinterpret_cast<const std::uint8_t*>(terminated.data()), terminated.size()});
        UniqueHandle thread{::CreateRemoteThread(
            process, nullptr, 0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library),
            remote_name, 0, nullptr)};
        if (!thread || ::WaitForSingleObject(thread.get(), 15000) != WAIT_OBJECT_0) {
            throw MappingError("target LoadLibraryA timed out");
        }
        ::VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
    } catch (...) {
        ::VirtualFreeEx(process, remote_name, 0, MEM_RELEASE);
        throw;
    }
}

RemoteModule ensure_remote_module(
    std::uint32_t process_id,
    HANDLE process,
    const ProcessMemory& memory,
    std::string_view module_name) {
    if (auto module = find_remote_module(process_id, widen_module_name(module_name))) {
        return *module;
    }
    const auto host_name = loader_host_module_name(module_name);
    if (auto module = find_remote_module(process_id, host_name)) {
        return *module;
    }
    load_remote_module(process_id, process, memory, module_name);
    if (auto module = find_remote_module(process_id, widen_module_name(module_name))) {
        return *module;
    }
    if (auto module = find_remote_module(process_id, host_name)) {
        return *module;
    }
    throw MappingError("target loader did not expose imported module: " + std::string{module_name});
}

}





ManualMapResult manual_map_pe_dll(
    std::uint32_t process_id,
    std::span<const std::uint8_t> portable_executable) {
    if (process_id == 0) {
        throw MappingError("target process id cannot be zero");
    }
    const auto plan = makima::platform::PortableExecutableMappingPlanner{}.create_plan(
        portable_executable);
    if (!plan.unsupported_execution_steps.empty()) {
        throw MappingError("mapping plan contains an unsupported PE feature: " +
                           plan.unsupported_execution_steps.front());
    }
    if (plan.size_of_image == 0 || plan.size_of_headers == 0 ||
        plan.size_of_headers > portable_executable.size()) {
        throw MappingError("mapping plan has invalid image geometry");
    }

    UniqueHandle process{::OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SET_QUOTA | PROCESS_TERMINATE,
        FALSE, process_id)};
    if (!process) {
        throw MappingError("failed to open target process for mapping");
    }
    BOOL target_is_wow64 = FALSE;
    if (!::IsWow64Process(process.get(), &target_is_wow64)) {
        throw MappingError("failed to query target process architecture");
    }
    if (target_is_wow64 != FALSE) {
        throw MappingError("a PE32+ image cannot be mapped into a WOW64 target");
    }
    ProcessMemory memory{process.get()};
    void* remote_image = ::VirtualAllocEx(
        process.get(), reinterpret_cast<void*>(plan.preferred_image_base),
        plan.size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_image == nullptr) {
        remote_image = ::VirtualAllocEx(
            process.get(), nullptr, plan.size_of_image,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }
    const auto image_base = reinterpret_cast<VirtualAddress>(remote_image);
    if (image_base == 0) {
        throw MappingError("target image allocation failed");
    }

    ManualMapResult result{image_base, image_base + plan.entry_point_rva};
    VirtualAddress registered_function_table = 0;
    VirtualAddress delete_function_table = 0;
    std::size_t completed_tls_callbacks = 0;
    std::vector<VirtualAddress> loaded_dependencies;
    try {
        std::vector<std::uint8_t> mapped_image(plan.size_of_image);
        const auto headers = checked_file_range(portable_executable, 0, plan.size_of_headers);
        std::copy(headers.begin(), headers.end(), mapped_image.begin());

        for (const auto& section : plan.sections) {
            if (section.raw_size == 0) {
                continue;
            }
            const auto source = checked_file_range(
                portable_executable, section.raw_offset, section.raw_size);
            std::copy(source.begin(), source.end(), mapped_image.begin() + section.virtual_address);
        }

        const auto relocation_delta = image_base - plan.preferred_image_base;
        if (relocation_delta != 0) {
            if (plan.relocations.empty()) {
                throw MappingError(
                    "preferred image base was unavailable and the image has no relocation table");
            }
            for (const auto& relocation : plan.relocations) {
                if (relocation.type != IMAGE_REL_BASED_DIR64 ||
                    relocation.target_rva > mapped_image.size() - sizeof(std::uint64_t)) {
                    throw MappingError("mapping plan contains an invalid non-DIR64 relocation");
                }
                std::uint64_t target{};
                std::memcpy(&target, mapped_image.data() + relocation.target_rva, sizeof(target));
                target += relocation_delta;
                std::memcpy(mapped_image.data() + relocation.target_rva, &target, sizeof(target));
                ++result.applied_relocation_count;
            }
        }
        const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(mapped_image.data());
        auto* mapped_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(
            mapped_image.data() + dos_header->e_lfanew);
        mapped_headers->OptionalHeader.ImageBase = image_base;

        for (const auto& module : plan.imports) {
            const auto requested_name = widen_module_name(module.name);
            const auto host_name = loader_host_module_name(module.name);
            const bool dependency_was_loaded =
                find_remote_module(process_id, requested_name).has_value() ||
                find_remote_module(process_id, host_name).has_value();
            const auto remote_module = ensure_remote_module(
                process_id, process.get(), memory, module.name);
            if (!dependency_was_loaded &&
                std::ranges::find(loaded_dependencies, remote_module.base) ==
                    loaded_dependencies.end()) {
                loaded_dependencies.push_back(remote_module.base);
            }
            if (module.module_handle_rva != 0) {
                if (module.module_handle_rva > mapped_image.size() - sizeof(remote_module.base)) {
                    throw MappingError("delay import module-handle slot lies outside the image");
                }
                std::memcpy(
                    mapped_image.data() + module.module_handle_rva,
                    &remote_module.base,
                    sizeof(remote_module.base));
            }
            for (const auto& symbol : module.symbols) {
                const auto address = symbol.by_ordinal
                    ? resolve_remote_export_ordinal(process_id, remote_module, symbol.ordinal)
                    : resolve_remote_export(process_id, remote_module, symbol.name);
                if (address == 0) {
                    throw MappingError(
                        "manual mapper could not resolve " + module.name + "!" +
                        (symbol.by_ordinal ? "#" + std::to_string(symbol.ordinal) : symbol.name));
                }
                if (symbol.address_table_rva > mapped_image.size() - sizeof(address)) {
                    throw MappingError("import address table entry lies outside the image");
                }
                std::memcpy(
                    mapped_image.data() + symbol.address_table_rva, &address, sizeof(address));
                ++result.imported_symbol_count;
            }
        }

        write_exact(memory, image_base, mapped_image);

        if (!plan.exception_functions.empty()) {
            const auto exception_directory =
                mapped_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            const auto ntdll = require_remote_module(process_id, "ntdll.dll");
            const auto add_function_table = resolve_remote_export(
                process_id, ntdll, "RtlAddFunctionTable");
            delete_function_table = resolve_remote_export(
                process_id, ntdll, "RtlDeleteFunctionTable");
            if (add_function_table == 0 || delete_function_table == 0 ||
                !invoke_remote_three_args(
                    process.get(), memory, add_function_table,
                    image_base + exception_directory.VirtualAddress,
                    plan.exception_functions.size(), image_base, true)) {
                throw MappingError("failed to register remote unwind metadata");
            }
            registered_function_table = image_base + exception_directory.VirtualAddress;
        }

        for (const auto& section : plan.sections) {
            const auto size = std::max(section.virtual_size, section.raw_size);
            if (size != 0) {
                DWORD previous{};
                if (!::VirtualProtectEx(
                        process.get(), reinterpret_cast<void*>(image_base + section.virtual_address),
                        size, section_protection(section.access), &previous)) {
                    throw MappingError("failed to apply remote section protection");
                }
            }
        }
        DWORD previous{};
        if (!::VirtualProtectEx(
                process.get(), remote_image, plan.size_of_headers,
                PAGE_READONLY, &previous)) {
            throw MappingError("failed to protect remote image headers");
        }
        if (!::FlushInstructionCache(process.get(), remote_image, plan.size_of_image)) {
            throw MappingError("failed to flush target instruction cache");
        }

        for (const auto callback_rva : plan.tls_callback_rvas) {
            static_cast<void>(invoke_remote_three_args(
                process.get(), memory, image_base + callback_rva,
                image_base, DLL_PROCESS_ATTACH, 0, false));
            ++result.invoked_tls_callback_count;
            ++completed_tls_callbacks;
        }

        if (plan.entry_point_rva != 0) {
            result.entry_point_succeeded = invoke_remote_three_args(
                process.get(), memory, result.entry_point,
                image_base, DLL_PROCESS_ATTACH, 0, true);
            if (!result.entry_point_succeeded) {
                throw MappingError("mapped image entry point rejected process attach");
            }
        } else {
            result.entry_point_succeeded = true;
        }

        UniqueHandle lifecycle_job{::CreateJobObjectW(nullptr, nullptr)};
        if (!lifecycle_job ||
            !::AssignProcessToJobObject(lifecycle_job.get(), process.get())) {
            throw MappingError("failed to attach mapped process to lifecycle job");
        }
        auto* job_request = new (std::nothrow)
            ::makima::platform::windows::NativeJobInformationRequest{
                lifecycle_job.get(), 0, nullptr, 0};
        if (job_request == nullptr) {
            throw MappingError("failed to allocate mapper lifecycle request");
        }
        ::makima::process::launch::ChildLaunchState lifecycle_state{};
        lifecycle_state.process = process.get();
        lifecycle_state.image_base = image_base;
        lifecycle_state.job_request = job_request;
        lifecycle_state.job = lifecycle_job.get();
        lifecycle_state.mapping_state = 99;
        lifecycle_state.owned_job_request = job_request;
        const bool lifecycle_complete =
            ::makima::process::launch::terminate_child_job_and_restore_impersonation(
                &lifecycle_state, 0x63U) != 0;
        if (lifecycle_state.owned_job_request != nullptr) {
            delete lifecycle_state.owned_job_request;
            lifecycle_state.owned_job_request = nullptr;
        }
        if (!lifecycle_complete) {
            throw MappingError("mapped process lifecycle finalization failed");
        }
    } catch (...) {
        while (completed_tls_callbacks != 0) {
            --completed_tls_callbacks;
            try {
                static_cast<void>(invoke_remote_three_args(
                    process.get(), memory,
                    image_base + plan.tls_callback_rvas[completed_tls_callbacks],
                    image_base, DLL_PROCESS_DETACH, 0, false));
            } catch (...) {

            }
        }
        if (registered_function_table != 0 && delete_function_table != 0) {
            try {
                static_cast<void>(invoke_remote_three_args(
                    process.get(), memory, delete_function_table,
                    registered_function_table, 0, 0, true));
            } catch (...) {

            }
        }
        if (!loaded_dependencies.empty()) {
            try {
                const auto kernel32 = require_remote_module(process_id, "kernel32.dll");
                const auto free_library = resolve_remote_export(
                    process_id, kernel32, "FreeLibrary");
                if (free_library != 0) {
                    for (auto module = loaded_dependencies.rbegin();
                         module != loaded_dependencies.rend(); ++module) {
                        static_cast<void>(invoke_remote_three_args(
                            process.get(), memory, free_library, *module, 0, 0, true));
                    }
                }
            } catch (...) {

            }
        }
        ::VirtualFreeEx(process.get(), remote_image, 0, MEM_RELEASE);
        throw;
    }

    return result;
}

}
