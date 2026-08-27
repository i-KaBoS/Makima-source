#pragma once

#include <bcrypt.h>

namespace makima::network::shared {

[[nodiscard]] decltype(&BCryptGenRandom) resolve_bcrypt_random() noexcept;

}
