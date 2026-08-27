#include "security/privileges/privileges.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#include <windows.h>
#include <winternl.h>
#include <winsvc.h>
#include <oleauto.h>

namespace makima::security::privileges {

bool token_has_enabled_privilege(HANDLE token, const LUID& luid) noexcept;




void curve25519_field_multiply(
    std::int64_t output[10],
    const std::int64_t left[10],
    const std::int64_t right[10]) noexcept {
    const auto f0 = left[0];
    const auto f1 = left[1];
    const auto f2 = left[2];
    const auto f3 = left[3];
    const auto f4 = left[4];
    const auto f5 = left[5];
    const auto f6 = left[6];
    const auto f7 = left[7];
    const auto f8 = left[8];
    const auto f9 = left[9];
    const auto g0 = right[0];
    const auto g1 = right[1];
    const auto g2 = right[2];
    const auto g3 = right[3];
    const auto g4 = right[4];
    const auto g5 = right[5];
    const auto g6 = right[6];
    const auto g7 = right[7];
    const auto g8 = right[8];
    const auto g9 = right[9];

    const auto g1_19 = 19 * g1;
    const auto g2_19 = 19 * g2;
    const auto g3_19 = 19 * g3;
    const auto g4_19 = 19 * g4;
    const auto g5_19 = 19 * g5;
    const auto g6_19 = 19 * g6;
    const auto g7_19 = 19 * g7;
    const auto g8_19 = 19 * g8;
    const auto g9_19 = 19 * g9;
    const auto f1_2 = 2 * f1;
    const auto f3_2 = 2 * f3;
    const auto f5_2 = 2 * f5;
    const auto f7_2 = 2 * f7;
    const auto f9_2 = 2 * f9;

    std::int64_t h0 = f0 * g0 + f1_2 * g9_19 + f2 * g8_19 + f3_2 * g7_19 +
        f4 * g6_19 + f5_2 * g5_19 + f6 * g4_19 + f7_2 * g3_19 +
        f8 * g2_19 + f9_2 * g1_19;
    std::int64_t h1 = f0 * g1 + f1 * g0 + f2 * g9_19 + f3 * g8_19 +
        f4 * g7_19 + f5 * g6_19 + f6 * g5_19 + f7 * g4_19 +
        f8 * g3_19 + f9 * g2_19;
    std::int64_t h2 = f0 * g2 + f1_2 * g1 + f2 * g0 + f3_2 * g9_19 +
        f4 * g8_19 + f5_2 * g7_19 + f6 * g6_19 + f7_2 * g5_19 +
        f8 * g4_19 + f9_2 * g3_19;
    std::int64_t h3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 +
        f4 * g9_19 + f5 * g8_19 + f6 * g7_19 + f7 * g6_19 +
        f8 * g5_19 + f9 * g4_19;
    std::int64_t h4 = f0 * g4 + f1_2 * g3 + f2 * g2 + f3_2 * g1 +
        f4 * g0 + f5_2 * g9_19 + f6 * g8_19 + f7_2 * g7_19 +
        f8 * g6_19 + f9_2 * g5_19;
    std::int64_t h5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 +
        f4 * g1 + f5 * g0 + f6 * g9_19 + f7 * g8_19 +
        f8 * g7_19 + f9 * g6_19;
    std::int64_t h6 = f0 * g6 + f1_2 * g5 + f2 * g4 + f3_2 * g3 +
        f4 * g2 + f5_2 * g1 + f6 * g0 + f7_2 * g9_19 +
        f8 * g8_19 + f9_2 * g7_19;
    std::int64_t h7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 +
        f4 * g3 + f5 * g2 + f6 * g1 + f7 * g0 +
        f8 * g9_19 + f9 * g8_19;
    std::int64_t h8 = f0 * g8 + f1_2 * g7 + f2 * g6 + f3_2 * g5 +
        f4 * g4 + f5_2 * g3 + f6 * g2 + f7_2 * g1 +
        f8 * g0 + f9_2 * g9_19;
    std::int64_t h9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 +
        f4 * g5 + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;

    auto carry = (h0 + (std::int64_t{1} << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h4 + (std::int64_t{1} << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h1 + (std::int64_t{1} << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h5 + (std::int64_t{1} << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;
    carry = (h2 + (std::int64_t{1} << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h6 + (std::int64_t{1} << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;
    carry = (h3 + (std::int64_t{1} << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h7 + (std::int64_t{1} << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;
    carry = (h4 + (std::int64_t{1} << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h8 + (std::int64_t{1} << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;
    carry = (h9 + (std::int64_t{1} << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h0 + (std::int64_t{1} << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;

    output[0] = h0;
    output[1] = h1;
    output[2] = h2;
    output[3] = h3;
    output[4] = h4;
    output[5] = h5;
    output[6] = h6;
    output[7] = h7;
    output[8] = h8;
    output[9] = h9;
}



void enable_debug_and_driver_privileges() noexcept {
    static_cast<void>(enable_named_privilege(SE_DEBUG_NAME));
    static_cast<void>(enable_named_privilege(SE_LOAD_DRIVER_NAME));
}

}
