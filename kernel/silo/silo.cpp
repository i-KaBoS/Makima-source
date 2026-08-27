#include "kernel/silo/silo.hpp"

#include <cstddef>
#include <span>
#include <string_view>

namespace makima::kernel::silo {
namespace {

constexpr std::uint32_t event_modify_state_access = 0x0002;
constexpr std::size_t lsa_registration_output_size = sizeof(std::uint32_t);

[[nodiscard]] const wchar_t* lsa_initialized_event_name() {
    static const wchar_t* value =
        allocate_lsa_authentication_initialized_event_name(
            reinterpret_cast<const std::uint16_t*>(0x1414DAB2Eull));
    return value;
}

[[nodiscard]] const wchar_t* ksecdd_device_path() {
    static const wchar_t* value = allocate_ksecdd_device_path(
        reinterpret_cast<const std::uint16_t*>(0x1414DAB82ull));
    return value;
}

void close_handle(NativeApi& api, NativeHandle handle) noexcept {
    if (handle == 0 || !api.close) {
        return;
    }
    try {
        api.close(handle);
    } catch (...) {

    }
}

[[nodiscard]] std::span<const std::byte> request_bytes(
    const KsecFunctionReturnRequest& request) noexcept {
    return std::as_bytes(std::span{&request, std::size_t{1}});
}

}



bool register_ksecdd_silo_lsa(SiloContext& context, NativeApi& api) {
    if (!api.open_object || !api.signal_event || !api.open_device ||
        !api.device_control || !api.close) {
        throw_native_api_unavailable();
    }

    context.lsa_registered = false;
    const auto initialization_event =
        api.open_object(lsa_initialized_event_name(), event_modify_state_access);
    if (initialization_event == 0) {
        return false;
    }

    const auto signal_status = api.signal_event(initialization_event);
    close_handle(api, initialization_event);
    if (!signal_status.success()) {
        return false;
    }

    const auto device_handle = api.open_device(ksecdd_device_path());
    if (device_handle == 0) {
        return false;
    }
    if (context.ksecdd != 0 && context.ksecdd != device_handle) {
        close_handle(api, context.ksecdd);
    }
    context.ksecdd = device_handle;

    const auto registration = api.device_control(
        context.ksecdd,
        ksecdd_register_lsa_ioctl,
        {},
        lsa_registration_output_size);
    context.lsa_registered = registration.status.success();
    return context.lsa_registered;
}



DeviceControlResult set_ksecdd_function_return(
    SiloContext& context,
    NativeApi& api,
    std::uint64_t kernel_function,
    std::uint64_t argument) {
    if (context.ksecdd == 0 || !context.lsa_registered) {
        throw_invalid_silo_state();
    }
    if (!api.device_control) {
        throw_native_api_unavailable();
    }

    const KsecFunctionReturnRequest request{kernel_function, argument};
    return api.device_control(
        context.ksecdd,
        ksecdd_set_function_return_ioctl,
        request_bytes(request),
        0);
}

}
