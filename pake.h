#ifndef pake_h
#define pake_h

#include <stdint.h>
#include <stdlib.h>
#include "decaf.h"

// parameters from client init to be shared with server
typedef struct {
  uint8_t c[32];
  uint8_t C[32];
  uint8_t k_s[32];
  uint8_t P_u[32];  // users Identity pubkey
  uint8_t m_u[32];
} __attribute((packed)) UserRecord;

void server_init(uint8_t *p_s, uint8_t *P_s);
void client_init(const uint8_t *rwd, const size_t rwd_len, const uint8_t *P_s,  // input params
                 uint8_t k_s[32], uint8_t c[32], uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]);
void start_pake(const uint8_t *rwd, const size_t rwd_len, // input params
                uint8_t alpha[32], uint8_t x_u[32],      // output params
                uint8_t X_u[32], uint8_t sp[32]);
int server_pake(const uint8_t alpha[32], const uint8_t X_u[32],  // input params
                const uint8_t k_s[32], const uint8_t P_u[32],
                const uint8_t p_s[32],
                uint8_t beta[32], uint8_t X_s[32],               // output params
                uint8_t SK[DECAF_X25519_PUBLIC_BYTES]);
int user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t sp[32],
              const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32],
              const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32],
              const uint8_t P_s[32], const uint8_t X_s[32],
              uint8_t SK[DECAF_X25519_PUBLIC_BYTES]);

#endif // pake_h
