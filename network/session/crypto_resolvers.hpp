#pragma once

#include <bcrypt.h>

namespace makima::network::session {

[[nodiscard]] decltype(&BCryptOpenAlgorithmProvider)
resolve_bcrypt_open_algorithm_provider() noexcept;
[[nodiscard]] decltype(&BCryptSetProperty)
resolve_bcrypt_set_property() noexcept;
[[nodiscard]] decltype(&BCryptGenerateSymmetricKey)
resolve_bcrypt_generate_symmetric_key() noexcept;
[[nodiscard]] decltype(&BCryptEncrypt) resolve_bcrypt_encrypt() noexcept;

}
