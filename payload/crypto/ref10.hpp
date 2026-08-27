#pragma once

#include <array>
#include <cstdint>

namespace makima::payload::crypto::ref10 {

using FieldElement = std::array<std::int64_t, 10>;

struct GeP3 final {
    FieldElement X;
    FieldElement Y;
    FieldElement Z;
    FieldElement T;
};

struct GeCached final {
    FieldElement YplusX;
    FieldElement YminusX;
    FieldElement Z;
    FieldElement T2d;
};

struct GeP1P1 final {
    FieldElement X;
    FieldElement Y;
    FieldElement Z;
    FieldElement T;
};

static_assert(sizeof(FieldElement) == 80);
static_assert(sizeof(GeP3) == 320);
static_assert(sizeof(GeCached) == 320);
static_assert(sizeof(GeP1P1) == 320);

[[nodiscard]] std::uint8_t* fe_tobytes(
    std::uint8_t output[32],
    const FieldElement* input) noexcept;

[[nodiscard]] int ge_frombytes_negate_vartime(
    GeP3* output,
    const std::uint8_t encoded[32]) noexcept;

[[nodiscard]] GeP1P1* ge_add(
    GeP1P1* output,
    const GeP3* point,
    const GeCached* cached) noexcept;

}
