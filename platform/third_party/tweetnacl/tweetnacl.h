#pragma once

#ifdef __cplusplus
extern "C" {
#endif

int crypto_scalarmult(unsigned char* output, const unsigned char* scalar, const unsigned char* point);
int crypto_scalarmult_base(unsigned char* output, const unsigned char* scalar);
int crypto_sign_open(
    unsigned char* message,
    unsigned long long* message_length,
    const unsigned char* signed_message,
    unsigned long long signed_message_length,
    const unsigned char* public_key);

#ifdef __cplusplus
}
#endif
