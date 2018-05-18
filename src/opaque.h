#ifndef pake_h
#define pake_h

#include <stdint.h>
#include <stdlib.h>
#include "decaf.h"
#include <crypto_secretbox.h>

typedef struct {
  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  uint8_t p_u[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t mac[crypto_secretbox_MACBYTES];
} __attribute((packed)) C;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[DECAF_255_SCALAR_BYTES];
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  C c;
} __attribute((packed)) Opaque_UserRecord;

// data sent to S from U in login#1
typedef struct {
  uint8_t alpha[DECAF_X25519_PUBLIC_BYTES];
  uint8_t X_u[DECAF_X25519_PUBLIC_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t r[DECAF_X25519_PRIVATE_BYTES];
  uint8_t x_u[DECAF_X25519_PRIVATE_BYTES];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t beta[DECAF_X25519_PUBLIC_BYTES];
  uint8_t X_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  C c;
} __attribute((packed)) Opaque_ServerSession;

int storePwdFile(const uint8_t *sid, const uint8_t *U, const uint8_t *pw, Opaque_UserRecord *rec);
void usrSession(const uint8_t *sid, const uint8_t *ssid, const uint8_t *pw, Opaque_UserSession_Secret *sec, Opaque_UserSession *pub);
int srvSession(const uint8_t *sid, const uint8_t *ssid, const Opaque_UserSession *pub, const Opaque_UserRecord *rec, Opaque_ServerSession *resp, uint8_t *sk);
int userSessionEnd(const Opaque_ServerSession *resp, const Opaque_UserSession_Secret *sec, const uint8_t *pw, uint8_t *pk);

/* void pake_server_init(uint8_t *p_s, uint8_t *P_s); */
/* void pake_client_init(const uint8_t *rwd, const size_t rwd_len, const uint8_t *P_s,  // input params */
/*                       uint8_t k_s[32], uint8_t c[32], uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]); */
/* void pake_start_pake(const uint8_t *rwd, const size_t rwd_len, // input params */
/*                      uint8_t alpha[32], uint8_t x_u[32],      // output params */
/*                      uint8_t X_u[32], uint8_t sp[32]); */
/* int pake_server_pake(const uint8_t alpha[32], const uint8_t X_u[32],  // input params */
/*                      const uint8_t k_s[32], const uint8_t P_u[32], */
/*                      const uint8_t p_s[32], */
/*                      uint8_t beta[32], uint8_t X_s[32],               // output params */
/*                      uint8_t SK[DECAF_X25519_PUBLIC_BYTES]); */
/* int pake_user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t sp[32], */
/*                    const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32], */
/*                    const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32], */
/*                    const uint8_t P_s[32], const uint8_t X_s[32], */
/*                    uint8_t SK[DECAF_X25519_PUBLIC_BYTES]); */

#endif // pake_h
