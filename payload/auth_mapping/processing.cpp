#include "payload/auth_mapping/auth_mapping.hpp"

#include <cstdlib>
#include <new>

namespace makima::payload::auth_mapping {

std::uint64_t payload_fingerprint(std::span<const std::byte> bytes) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const std::byte value : bytes) {
        hash ^= std::to_integer<std::uint8_t>(value);
        hash *= 1099511628211ULL;
    }
    return hash;
}





PolymorphicNarrowStringOwner* destroy_base_mapping_result(
    PolymorphicNarrowStringOwner* owner,
    std::uint32_t deletion_flag) noexcept {
    owner->vtable = 0x14149E480ull;
    release_owned_narrow_string_state(owner->text);

    if (deletion_flag != 0U) {
        ::operator delete(owner, sizeof(PolymorphicNarrowStringOwner));
    }
    return owner;
}

}
