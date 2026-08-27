#pragma once

#include "kernel/silo/silo.hpp"

namespace makima::kernel::silo {



struct ServerSiloLifetime final {
    ServerSiloLifetime() = default;
    ServerSiloLifetime(const ServerSiloLifetime&) = delete;
    ServerSiloLifetime& operator=(const ServerSiloLifetime&) = delete;
    ~ServerSiloLifetime() noexcept;

    NativeHandle job{};
    NativeHandle deletion_event{};
    wchar_t* root_path{};
};

}
