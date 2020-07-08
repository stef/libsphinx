#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include "common.h"

#include <stdio.h> // todo remove

#ifndef HAVE_SODIUM_HKDF
#include "aux/crypto_kdf_hkdf_sha256.h"
#endif

// enveloping function as specified in the ietf cfrg draft https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06#section-4
int opaque_envelope(const uint8_t *rwd, const uint8_t *SecEnv, const size_t SecEnv_len,
                     const uint8_t *ClrEnv, const size_t ClrEnv_len,
                     uint8_t *envelope, // must be of size: crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len+crypto_hash_sha256_BYTES
                     // len(nonce|SecEnv|ClrEnv|hmacTag)
                     uint8_t export_key[crypto_hash_sha256_BYTES]) {
  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope) return 1;
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv0 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv0 ");
#endif

  // (2) Set E = Nonce | ....
  randombytes(envelope,crypto_hash_sha256_BYTES);


  size_t tmp;
  if(__builtin_add_overflow(2*crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  uint8_t keys[tmp];

  // KEYS = HKDF-Expand(key=RwdU, info=(nonce | "EnvU"), Length=LS+LH+LH)
  // info
  char ctx[crypto_hash_sha256_BYTES+4];
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);
  memcpy(ctx+crypto_hash_sha256_BYTES,"EnvU",4);
  crypto_kdf_hkdf_sha256_expand(keys, sizeof keys, ctx, sizeof ctx /*nonce|"EnvU"*/, rwd);

  uint8_t *c = envelope+crypto_hash_sha256_BYTES;
  if(SecEnv) {
    //(1) Set C = SecEnv XOR PAD
    //(2) Set E = nonce | C | ...
    size_t i;
    for(i=0;i<SecEnv_len;i++) c[i]=SecEnv[i]^keys[i];
  }
  //(2) Set E = nonce | C | ClrEnv
  if(ClrEnv) memcpy(c+SecEnv_len, ClrEnv, ClrEnv_len);

  //(3) Set T = HMAC(E,HmacKey)
  uint8_t *hmackey=keys+SecEnv_len;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp,ClrEnv_len, &tmp)) return 1;
  crypto_auth_hmacsha256(envelope + crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len, // out
                         envelope,                                                  // in
                         crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len,            // len(in)
                         hmackey);                                                  // key
  uint8_t *ekey = keys+SecEnv_len+crypto_hash_sha256_BYTES;
  if(export_key) memcpy(export_key,ekey,crypto_hash_sha256_BYTES);

#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv1 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv1 ");
  dump(ekey,crypto_hash_sha256_BYTES, "export_key ");
  dump(envelope,crypto_hash_sha256_BYTES*2+SecEnv_len+ClrEnv_len, "envelope ");
#endif

  return 0;
}

int opaque_envelope_open(const uint8_t *rwd, const uint8_t *envelope,
                         uint8_t *SecEnv, const size_t SecEnv_len,
                         uint8_t *ClrEnv, const size_t ClrEnv_len,
                         uint8_t export_key[crypto_hash_sha256_BYTES]) {

  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope) return 1;

#ifdef TRACE
  dump(envelope,crypto_hash_sha256_BYTES*2+SecEnv_len+ClrEnv_len, "open envelope ");
#endif

  char ctx[crypto_hash_sha256_BYTES+4];
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);
  memcpy(ctx+crypto_hash_sha256_BYTES,"EnvU",4);

  size_t tmp;
  if(__builtin_add_overflow(2*crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;

  uint8_t keys[tmp];
  // KEYS = HKDF-Expand(key=RwdU, info=(nonce | "EnvU"), Length=LS+LH+LH)
  crypto_kdf_hkdf_sha256_expand(keys, sizeof keys, ctx, crypto_hash_sha256_BYTES+4 /*nonce|"EnvU"*/, rwd);

  uint8_t *hmackey=keys+SecEnv_len;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp,ClrEnv_len, &tmp)) return 1;

  if(-1 == crypto_auth_hmacsha256_verify(envelope + crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len, // tag
                                         envelope, crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len,  // in, inlen
                                         hmackey)) {
    return 1;
  }

  const uint8_t *c = envelope+crypto_hash_sha256_BYTES;
  // decrypt SecEnv
  if(SecEnv) {
    size_t i;
    for(i=0;i<SecEnv_len;i++) SecEnv[i]=c[i]^keys[i];
  }

  // return ClrEnv
  if (ClrEnv) memcpy(ClrEnv,c+SecEnv_len,ClrEnv_len);

  uint8_t *ekey = keys+SecEnv_len+crypto_hash_sha256_BYTES;
  if(export_key) memcpy(export_key,ekey,crypto_hash_sha256_BYTES);

#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv ");
  dump(ekey,crypto_hash_sha256_BYTES, "export_key ");
#endif

  return 0;
}
