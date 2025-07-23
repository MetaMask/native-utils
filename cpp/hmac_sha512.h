/*
 * Standalone HMAC-SHA512 implementation
 * Based on Olivier Gay's implementation (BSD license)
 * Self-contained, no external dependencies
 */

#ifndef HMAC_SHA512_H
#define HMAC_SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE 128

/**
 * Compute HMAC-SHA512
 * @param key - The key
 * @param key_len - Key length in bytes
 * @param data - The data to authenticate
 * @param data_len - Data length in bytes
 * @param output - Output buffer (must be at least 64 bytes)
 */
void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t output[SHA512_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_SHA512_H */ 