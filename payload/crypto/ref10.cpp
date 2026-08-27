#include "payload/crypto/ref10.hpp"

#include "security/privileges/privileges.hpp"

#include <cstddef>
#include <cstring>

namespace makima::payload::crypto::ref10 {

namespace {

constexpr FieldElement edwards_d{
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116,
};

constexpr FieldElement sqrt_minus_one{
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482,
};

[[nodiscard]] std::uint64_t load_3(const std::uint8_t* input) noexcept {
    return static_cast<std::uint64_t>(input[0]) |
        (static_cast<std::uint64_t>(input[1]) << 8) |
        (static_cast<std::uint64_t>(input[2]) << 16);
}

[[nodiscard]] std::uint64_t load_4(const std::uint8_t* input) noexcept {
    return load_3(input) | (static_cast<std::uint64_t>(input[3]) << 24);
}

void field_from_bytes(FieldElement& output, const std::uint8_t input[32]) noexcept {
    std::int64_t h0 = static_cast<std::int64_t>(load_4(input));
    std::int64_t h1 = static_cast<std::int64_t>(load_3(input + 4) << 6);
    std::int64_t h2 = static_cast<std::int64_t>(load_3(input + 7) << 5);
    std::int64_t h3 = static_cast<std::int64_t>(load_3(input + 10) << 3);
    std::int64_t h4 = static_cast<std::int64_t>(load_3(input + 13) << 2);
    std::int64_t h5 = static_cast<std::int64_t>(load_4(input + 16));
    std::int64_t h6 = static_cast<std::int64_t>(load_3(input + 20) << 7);
    std::int64_t h7 = static_cast<std::int64_t>(load_3(input + 23) << 5);
    std::int64_t h8 = static_cast<std::int64_t>(load_3(input + 26) << 4);
    std::int64_t h9 = static_cast<std::int64_t>((load_3(input + 29) & 0x7fffffU) << 2);

    auto carry = (h9 + (std::int64_t{1} << 24)) >> 25;
    h0 += carry * 19;
    h9 -= carry << 25;
    carry = (h1 + (std::int64_t{1} << 24)) >> 25;
    h2 += carry;
    h1 -= carry << 25;
    carry = (h3 + (std::int64_t{1} << 24)) >> 25;
    h4 += carry;
    h3 -= carry << 25;
    carry = (h5 + (std::int64_t{1} << 24)) >> 25;
    h6 += carry;
    h5 -= carry << 25;
    carry = (h7 + (std::int64_t{1} << 24)) >> 25;
    h8 += carry;
    h7 -= carry << 25;
    carry = (h0 + (std::int64_t{1} << 25)) >> 26;
    h1 += carry;
    h0 -= carry << 26;
    carry = (h2 + (std::int64_t{1} << 25)) >> 26;
    h3 += carry;
    h2 -= carry << 26;
    carry = (h4 + (std::int64_t{1} << 25)) >> 26;
    h5 += carry;
    h4 -= carry << 26;
    carry = (h6 + (std::int64_t{1} << 25)) >> 26;
    h7 += carry;
    h6 -= carry << 26;
    carry = (h8 + (std::int64_t{1} << 25)) >> 26;
    h9 += carry;
    h8 -= carry << 26;

    output = {h0, h1, h2, h3, h4, h5, h6, h7, h8, h9};
}

void field_add(
    FieldElement& output,
    const FieldElement& left,
    const FieldElement& right) noexcept {
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = left[index] + right[index];
    }
}

void field_subtract(
    FieldElement& output,
    const FieldElement& left,
    const FieldElement& right) noexcept {
    for (std::size_t index = 0; index < output.size(); ++index) {
        output[index] = left[index] - right[index];
    }
}

void field_multiply(
    FieldElement& output,
    const FieldElement& left,
    const FieldElement& right) noexcept {
    ::makima::security::privileges::curve25519_field_multiply(
        output.data(), left.data(), right.data());
}

void field_square(FieldElement& output, const FieldElement& input) noexcept {
    field_multiply(output, input, input);
}

void field_pow_22523(FieldElement& output, const FieldElement& input) noexcept {
    FieldElement t0{};
    FieldElement t1{};
    FieldElement t2{};
    field_square(t0, input);
    field_square(t1, t0);
    field_square(t1, t1);
    field_multiply(t1, input, t1);
    field_multiply(t0, t0, t1);
    field_square(t0, t0);
    field_multiply(t0, t1, t0);
    field_square(t1, t0);
    for (int index = 1; index < 5; ++index) field_square(t1, t1);
    field_multiply(t0, t1, t0);
    field_square(t1, t0);
    for (int index = 1; index < 10; ++index) field_square(t1, t1);
    field_multiply(t1, t1, t0);
    field_square(t2, t1);
    for (int index = 1; index < 20; ++index) field_square(t2, t2);
    field_multiply(t1, t2, t1);
    field_square(t1, t1);
    for (int index = 1; index < 10; ++index) field_square(t1, t1);
    field_multiply(t0, t1, t0);
    field_square(t1, t0);
    for (int index = 1; index < 50; ++index) field_square(t1, t1);
    field_multiply(t1, t1, t0);
    field_square(t2, t1);
    for (int index = 1; index < 100; ++index) field_square(t2, t2);
    field_multiply(t1, t2, t1);
    field_square(t1, t1);
    for (int index = 1; index < 50; ++index) field_square(t1, t1);
    field_multiply(t0, t1, t0);
    field_square(t0, t0);
    field_square(t0, t0);
    field_multiply(output, t0, input);
}

[[nodiscard]] bool field_is_nonzero(const FieldElement& input) noexcept {
    std::uint8_t encoded[32]{};
    (void)fe_tobytes(encoded, &input);
    std::uint8_t difference = 0;
    for (const auto value : encoded) difference |= value;
    return difference != 0;
}

[[nodiscard]] bool field_is_negative(const FieldElement& input) noexcept {
    std::uint8_t encoded[32]{};
    (void)fe_tobytes(encoded, &input);
    return (encoded[0] & 1U) != 0;
}

}




std::uint8_t* fe_tobytes(
    std::uint8_t output[32],
    const FieldElement* input) noexcept {
    std::int64_t h0 = (*input)[0];
    std::int64_t h1 = (*input)[1];
    std::int64_t h2 = (*input)[2];
    std::int64_t h3 = (*input)[3];
    std::int64_t h4 = (*input)[4];
    std::int64_t h5 = (*input)[5];
    std::int64_t h6 = (*input)[6];
    std::int64_t h7 = (*input)[7];
    std::int64_t h8 = (*input)[8];
    std::int64_t h9 = (*input)[9];

    std::int64_t q = (19 * h9 + (std::int64_t{1} << 24)) >> 25;
    q = (h0 + q) >> 26;
    q = (h1 + q) >> 25;
    q = (h2 + q) >> 26;
    q = (h3 + q) >> 25;
    q = (h4 + q) >> 26;
    q = (h5 + q) >> 25;
    q = (h6 + q) >> 26;
    q = (h7 + q) >> 25;
    q = (h8 + q) >> 26;
    q = (h9 + q) >> 25;

    h0 += 19 * q;
    auto carry = h0 >> 26;
    h1 += carry;
    h0 -= carry * (std::int64_t{1} << 26);
    carry = h1 >> 25;
    h2 += carry;
    h1 -= carry * (std::int64_t{1} << 25);
    carry = h2 >> 26;
    h3 += carry;
    h2 -= carry * (std::int64_t{1} << 26);
    carry = h3 >> 25;
    h4 += carry;
    h3 -= carry * (std::int64_t{1} << 25);
    carry = h4 >> 26;
    h5 += carry;
    h4 -= carry * (std::int64_t{1} << 26);
    carry = h5 >> 25;
    h6 += carry;
    h5 -= carry * (std::int64_t{1} << 25);
    carry = h6 >> 26;
    h7 += carry;
    h6 -= carry * (std::int64_t{1} << 26);
    carry = h7 >> 25;
    h8 += carry;
    h7 -= carry * (std::int64_t{1} << 25);
    carry = h8 >> 26;
    h9 += carry;
    h8 -= carry * (std::int64_t{1} << 26);
    carry = h9 >> 25;
    h9 -= carry * (std::int64_t{1} << 25);

    output[0] = static_cast<std::uint8_t>(h0 >> 0);
    output[1] = static_cast<std::uint8_t>(h0 >> 8);
    output[2] = static_cast<std::uint8_t>(h0 >> 16);
    output[3] = static_cast<std::uint8_t>((h0 >> 24) | (h1 << 2));
    output[4] = static_cast<std::uint8_t>(h1 >> 6);
    output[5] = static_cast<std::uint8_t>(h1 >> 14);
    output[6] = static_cast<std::uint8_t>((h1 >> 22) | (h2 << 3));
    output[7] = static_cast<std::uint8_t>(h2 >> 5);
    output[8] = static_cast<std::uint8_t>(h2 >> 13);
    output[9] = static_cast<std::uint8_t>((h2 >> 21) | (h3 << 5));
    output[10] = static_cast<std::uint8_t>(h3 >> 3);
    output[11] = static_cast<std::uint8_t>(h3 >> 11);
    output[12] = static_cast<std::uint8_t>((h3 >> 19) | (h4 << 6));
    output[13] = static_cast<std::uint8_t>(h4 >> 2);
    output[14] = static_cast<std::uint8_t>(h4 >> 10);
    output[15] = static_cast<std::uint8_t>(h4 >> 18);
    output[16] = static_cast<std::uint8_t>(h5 >> 0);
    output[17] = static_cast<std::uint8_t>(h5 >> 8);
    output[18] = static_cast<std::uint8_t>(h5 >> 16);
    output[19] = static_cast<std::uint8_t>((h5 >> 24) | (h6 << 1));
    output[20] = static_cast<std::uint8_t>(h6 >> 7);
    output[21] = static_cast<std::uint8_t>(h6 >> 15);
    output[22] = static_cast<std::uint8_t>((h6 >> 23) | (h7 << 3));
    output[23] = static_cast<std::uint8_t>(h7 >> 5);
    output[24] = static_cast<std::uint8_t>(h7 >> 13);
    output[25] = static_cast<std::uint8_t>((h7 >> 21) | (h8 << 4));
    output[26] = static_cast<std::uint8_t>(h8 >> 4);
    output[27] = static_cast<std::uint8_t>(h8 >> 12);
    output[28] = static_cast<std::uint8_t>((h8 >> 20) | (h9 << 6));
    output[29] = static_cast<std::uint8_t>(h9 >> 2);
    output[30] = static_cast<std::uint8_t>(h9 >> 10);
    output[31] = static_cast<std::uint8_t>(h9 >> 18);
    return output;
}




int ge_frombytes_negate_vartime(
    GeP3* output,
    const std::uint8_t encoded[32]) noexcept {
    FieldElement u{};
    FieldElement v{};
    FieldElement v3{};
    FieldElement vxx{};
    FieldElement check{};

    field_from_bytes(output->Y, encoded);
    output->Z = {};
    output->Z[0] = 1;
    field_square(u, output->Y);
    field_multiply(v, u, edwards_d);
    field_subtract(u, u, output->Z);
    field_add(v, v, output->Z);

    field_square(v3, v);
    field_multiply(v3, v3, v);
    field_square(output->X, v3);
    field_multiply(output->X, output->X, v);
    field_multiply(output->X, output->X, u);
    field_pow_22523(output->X, output->X);
    field_multiply(output->X, output->X, v3);
    field_multiply(output->X, output->X, u);

    field_square(vxx, output->X);
    field_multiply(vxx, vxx, v);
    field_subtract(check, vxx, u);
    if (field_is_nonzero(check)) {
        field_add(check, vxx, u);
        if (field_is_nonzero(check)) return -1;
        field_multiply(output->X, output->X, sqrt_minus_one);
    }

    if (field_is_negative(output->X) == ((encoded[31] >> 7) != 0)) {
        for (auto& limb : output->X) limb = -limb;
    }
    field_multiply(output->T, output->X, output->Y);
    return 0;
}





GeP1P1* ge_add(
    GeP1P1* output,
    const GeP3* point,
    const GeCached* cached) noexcept {
    FieldElement twice_z{};
    for (std::size_t index = 0; index < output->X.size(); ++index) {
        output->X[index] = point->Y[index] + point->X[index];
        output->Y[index] = point->Y[index] - point->X[index];
    }
    ::makima::security::privileges::curve25519_field_multiply(
        output->Z.data(), output->X.data(), cached->YplusX.data());
    ::makima::security::privileges::curve25519_field_multiply(
        output->Y.data(), output->Y.data(), cached->YminusX.data());
    ::makima::security::privileges::curve25519_field_multiply(
        output->T.data(), cached->T2d.data(), point->T.data());
    ::makima::security::privileges::curve25519_field_multiply(
        output->X.data(), point->Z.data(), cached->Z.data());
    for (std::size_t index = 0; index < output->X.size(); ++index) {
        twice_z[index] = output->X[index] + output->X[index];
        output->X[index] = output->Z[index] - output->Y[index];
        output->Y[index] = output->Z[index] + output->Y[index];
        output->Z[index] = twice_z[index] + output->T[index];
        output->T[index] = twice_z[index] - output->T[index];
    }
    return output;
}

}
