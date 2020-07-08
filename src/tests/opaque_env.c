#include <stdio.h>
#include <stdint.h>
#ifndef HAVE_SODIUM_HKDF
#include "../aux/crypto_kdf_hkdf_sha256.h"
#endif
#include "../opaque_envelope.h"

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  printf("%s ",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

int main(void) {
  printf("testing OPAQUE enveloping\n");

  uint8_t rwd[32]={0},
    SecEnv[80]={0},
    ClrEnv[80]={0},
    export_key[crypto_hash_sha256_BYTES],
    env[crypto_hash_sha256_BYTES+ sizeof(SecEnv)+sizeof(ClrEnv)+crypto_hash_sha256_BYTES];

  opaque_envelope(rwd, SecEnv, sizeof SecEnv, ClrEnv, sizeof ClrEnv, env, export_key);
  dump(env, sizeof env, "env");
  dump(export_key, sizeof export_key, "export_key");
  printf("opening\n");
  if(0!=opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail\n");
  }
  dump(SecEnv, sizeof SecEnv, "SecEnv");
  dump(ClrEnv, sizeof ClrEnv, "ClrEnv");
  dump(export_key, sizeof export_key, "export_key");

  // testing with random values
  printf("testing with random values\n");
  randombytes(SecEnv, sizeof SecEnv);
  randombytes(ClrEnv, sizeof ClrEnv);
  randombytes(rwd, sizeof rwd);
  opaque_envelope(rwd, SecEnv, sizeof SecEnv, ClrEnv, sizeof ClrEnv, env, export_key);
  if(0!=opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail %d\n", __LINE__);
  }
  printf("testing with corrupted envelope\n");
  env[0]++;
  if(0==opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail\n");
  }

  printf("testing with null ClrEnv\n");
  if(0==opaque_envelope(rwd, SecEnv, sizeof SecEnv, 0, sizeof ClrEnv, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0!=opaque_envelope(rwd, SecEnv, sizeof SecEnv, 0, 0, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0==opaque_envelope(rwd, SecEnv, sizeof SecEnv, ClrEnv, 0, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }

  if(0==opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, 0, sizeof ClrEnv, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0!=opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, 0, 0, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0==opaque_envelope_open(rwd, env, SecEnv, sizeof SecEnv, ClrEnv, 0, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }

  printf("testing with null SecEnv\n");
  if(0==opaque_envelope(rwd, 0, sizeof SecEnv, ClrEnv, sizeof ClrEnv, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0!=opaque_envelope(rwd, 0, 0, ClrEnv, sizeof ClrEnv, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0==opaque_envelope(rwd, 0, sizeof SecEnv, ClrEnv, sizeof ClrEnv, env, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }

  if(0==opaque_envelope_open(rwd, env, 0, sizeof SecEnv, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0!=opaque_envelope_open(rwd, env, 0, 0, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  if(0==opaque_envelope_open(rwd, env, 0, sizeof SecEnv, ClrEnv, sizeof ClrEnv, export_key)) {
    printf("fail %d\n", __LINE__);
    exit(1);
  }
  printf("ok\n");

  return 0;
}
