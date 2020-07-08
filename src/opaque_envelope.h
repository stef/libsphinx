#ifndef opaque_envelope_h
#define opaque_envelope_h

#include <stdlib.h>
#include <stdint.h>
#include <sodium.h>

int opaque_envelope(const uint8_t *rwd, const uint8_t *SecEnv, const size_t SecEnv_len,
                     const uint8_t *ClrEnv, const size_t ClrEnv_len,
                     uint8_t *envelope, // must be of size: crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len+crypto_hash_sha256_BYTES
                     // len(nonce|SecEnv|ClrEnv|hmacTag)
                     uint8_t export_key[crypto_hash_sha256_BYTES]);
int opaque_envelope_open(const uint8_t *rwd, const uint8_t *envelope,
                         uint8_t *SecEnv, const size_t SecEnv_len,
                         uint8_t *ClrEnv, const size_t ClrEnv_len,
                         uint8_t export_key[crypto_hash_sha256_BYTES]);
#endif // opaque_envelope_h
