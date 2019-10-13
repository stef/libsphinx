#ifndef sphinx_h
#define sphinx_h

#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#define SPHINX_255_SCALAR_BYTES crypto_core_ristretto255_SCALARBYTES
#define SPHINX_255_SER_BYTES crypto_core_ristretto255_BYTES

int sphinx_challenge(const uint8_t *pwd, const size_t p_len,
                     const uint8_t *salt,
                     const size_t salt_len,
                     uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
                     uint8_t chal[crypto_core_ristretto255_BYTES]);
int sphinx_respond(const uint8_t chal[crypto_core_ristretto255_BYTES],
                   const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t resp[crypto_core_ristretto255_BYTES]);
int sphinx_finish(const uint8_t *pwd, const size_t p_len,
                  const uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t resp[crypto_core_ristretto255_BYTES],
                  const uint8_t salt[crypto_pwhash_SALTBYTES],
                  uint8_t rwd[crypto_core_ristretto255_BYTES]);

#endif // sphinx_h
