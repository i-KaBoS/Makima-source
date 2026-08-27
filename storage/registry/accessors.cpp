#include "storage/registry/registry.hpp"

#include <array>
#include <windows.h>

namespace makima::storage::registry {

namespace {
alignas(void*) std::array<char, 0x30> integrity_capture_state{};
bool integrity_capture_in_use = false;


alignas(void*) std::byte registry_dispatch_state{};
alignas(void*) std::byte registry_iteration_state{};
bool registry_host_objects_active = false;

}

char* integrity_capture_buffer() noexcept {
    if (integrity_capture_in_use) return nullptr;
    integrity_capture_in_use = true;
    return integrity_capture_state.data();
}

void integrity_capture_storage_release(char* buffer, std::size_t capacity) noexcept {
    if (buffer == nullptr || capacity == 0) return;
    SecureZeroMemory(buffer, capacity);
    if (buffer == integrity_capture_state.data()) integrity_capture_in_use = false;
}


void* registry_dispatch_state_address() noexcept {
    return &registry_dispatch_state;
}


void* registry_iteration_state_address() noexcept {
    return &registry_iteration_state;
}

struct ReleasableObject {
    virtual void reserved_0() noexcept = 0;
    virtual void reserved_1() noexcept = 0;
    virtual void release() noexcept = 0;
};



void release_registry_host_interfaces(void* object) noexcept {
    if (object != nullptr) {
        auto** slots = reinterpret_cast<ReleasableObject**>(object);
        if (slots[2] != nullptr) slots[2]->release();
        if (slots[3] != nullptr) slots[3]->release();
    }
    registry_host_objects_active = false;
}

}
