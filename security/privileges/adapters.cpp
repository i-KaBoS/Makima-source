#include "security/privileges/privileges.hpp"

#include <cstddef>
#include <windows.h>

namespace makima::security::privileges {

void clear_sensitive_privilege_material(void* memory, std::size_t size) noexcept {
    if (memory != nullptr && size != 0) SecureZeroMemory(memory, size);
}

}
