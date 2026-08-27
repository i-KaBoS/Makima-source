#include "process/execution/execution.hpp"

#if defined(_MSC_VER)
extern "C" void __cdecl _Init_thread_abort(int*) noexcept;
#endif

namespace makima::process::execution {
namespace {

int remote_thread_initialization_epoch{};
int remote_allocation_initialization_epoch{};
int parameter_block_initialization_epoch{};
int trampoline_initialization_epoch{};
int thread_context_initialization_epoch{};
int completion_event_initialization_epoch{};
int process_handle_initialization_epoch{};

void abort_initialization(int& initialization_epoch) noexcept {
#if defined(_MSC_VER)
    _Init_thread_abort(&initialization_epoch);
#else
    initialization_epoch = 0;
#endif
}

}


void abort_remote_thread_initialization() noexcept {
    abort_initialization(remote_thread_initialization_epoch);
}


void abort_remote_allocation_initialization() noexcept {
    abort_initialization(remote_allocation_initialization_epoch);
}


void abort_parameter_block_initialization() noexcept {
    abort_initialization(parameter_block_initialization_epoch);
}


void abort_trampoline_initialization() noexcept {
    abort_initialization(trampoline_initialization_epoch);
}


void abort_thread_context_initialization() noexcept {
    abort_initialization(thread_context_initialization_epoch);
}


void abort_completion_event_initialization() noexcept {
    abort_initialization(completion_event_initialization_epoch);
}


void abort_process_handle_initialization() noexcept {
    abort_initialization(process_handle_initialization_epoch);
}

}
