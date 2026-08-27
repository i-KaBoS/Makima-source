#include "security/privileges/privileges.hpp"

#include <windows.h>

namespace makima::security::privileges {

bool token_has_enabled_privilege(HANDLE token, const LUID& luid) noexcept {
    if (token == nullptr) return false;
    PRIVILEGE_SET requested{};
    requested.PrivilegeCount = 1;
    requested.Control = PRIVILEGE_SET_ALL_NECESSARY;
    requested.Privilege[0].Luid = luid;
    requested.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL enabled = FALSE;
    return PrivilegeCheck(token, &requested, &enabled) != FALSE && enabled != FALSE;
}

}
