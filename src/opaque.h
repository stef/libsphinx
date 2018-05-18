#ifndef opaque_h
#define opaque_h

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

typedef struct {
  uint8_t beta[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
} __attribute((packed)) Opaque_RegisterPub;

typedef struct {
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t k_s[DECAF_X25519_PRIVATE_BYTES];
} __attribute((packed)) Opaque_RegisterSec;

int storePwdFile(const uint8_t *pw, Opaque_UserRecord *rec);
void usrSession(const uint8_t *pw, Opaque_UserSession_Secret *sec, Opaque_UserSession *pub);
int srvSession(const Opaque_UserSession *pub, const Opaque_UserRecord *rec, Opaque_ServerSession *resp, uint8_t *sk);
int userSessionEnd(const Opaque_ServerSession *resp, const Opaque_UserSession_Secret *sec, const uint8_t *pw, uint8_t *pk);

void newUser(const uint8_t *pw, uint8_t *r, uint8_t *alpha);
int initUser(const uint8_t *alpha, Opaque_RegisterSec *sec, Opaque_RegisterPub *pub);
int registerUser(const uint8_t *pw, const uint8_t *r, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);
void saveUser(const Opaque_RegisterSec *sec, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);

#endif // opaque_h
