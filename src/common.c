#include "common.h"

#ifdef TRACE
void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  printf("%s ",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}
#endif // TRACE

#ifdef NORANDOM
void a_randombytes(void* const buf, const size_t len) {
  memset(buf,0xa,len);
}

void a_randomscalar(unsigned char* buf) {
  uint8_t tmp[64];
  a_randombytes(tmp, 64);
  crypto_core_ristretto255_scalar_reduce(buf, tmp);
}
#endif // NORANDOM

int sphinx_oprf(const uint8_t *pwd, const size_t pwd_len,
                const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                uint8_t key[crypto_generichash_BYTES]) {
  // F_k(pwd) = H(pwd, (H0(pwd))^k) for key k ∈ Z_q
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  sodium_mlock(h0,sizeof h0);
  // hash pwd with H0
  crypto_generichash(h0, sizeof h0, pwd, pwd_len, 0, 0); // todo add salt
#ifdef TRACE
  dump(h0, sizeof h0, "h0");
#endif
  unsigned char H0[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0,sizeof H0);
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);
#ifdef TRACE
  dump(H0, sizeof H0, "H0");
#endif

  // H0 ^ k
  unsigned char H0_k[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0_k,sizeof H0_k);
  if (crypto_scalarmult_ristretto255(H0_k, k, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    sodium_munlock(H0_k,sizeof H0_k);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef TRACE
  dump(H0_k, sizeof H0_k, "H0_k");
#endif

  // hash(pwd||H0^k)
  crypto_generichash_state state;
  sodium_mlock(&state, sizeof state);
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pwd, pwd_len);
  crypto_generichash_update(&state, H0_k, sizeof H0_k);
  crypto_generichash_final(&state, key, 32);
#ifdef TRACE
  dump(key, 32, "key");
#endif
  sodium_munlock(H0_k,sizeof H0_k);
  sodium_munlock(&state, sizeof state);

  return 0;
}

static void derive_secret(uint8_t mk[crypto_generichash_BYTES],
                          const uint8_t sec[crypto_scalarmult_BYTES * 3]) {
  // workaround hash sec from 96 bytes down to 64,
  // as blake can only handle 64 as a key
  uint8_t hashkey[64];
  sodium_mlock(hashkey,sizeof hashkey);
  crypto_generichash(hashkey, sizeof hashkey, sec, 96, 0, 0);
#ifdef TRACE
  dump(hashkey, 32, "hashkey");
#endif

  // and hash for the result SK = f_K(0)
  sphinx_f(hashkey, sizeof hashkey, 0, mk);
#ifdef TRACE
  dump(mk, 32, "mk");
#endif

  sodium_munlock(hashkey, sizeof(hashkey));
}

// implements server end of triple-dh
int sphinx_server_3dh(uint8_t mk[crypto_generichash_BYTES],
               const uint8_t ix[crypto_scalarmult_SCALARBYTES],
               const uint8_t ex[crypto_scalarmult_SCALARBYTES],
               const uint8_t Ip[crypto_scalarmult_BYTES],
               const uint8_t Ep[crypto_scalarmult_BYTES]) {
  uint8_t sec[crypto_scalarmult_BYTES * 3], *ptr = sec;
  sodium_mlock(sec, sizeof sec);

  if(0!=crypto_scalarmult(ptr,ix,Ep)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ip)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ep)) return 1;
#ifdef TRACE
  dump(sec, 96, "sec");
#endif

  derive_secret(mk, sec);

  sodium_munlock(sec,sizeof(sec));
  return 0;
}

// implements user end of triple-dh
int sphinx_user_3dh(uint8_t mk[crypto_generichash_BYTES],
             const uint8_t ix[crypto_scalarmult_SCALARBYTES],
             const uint8_t ex[crypto_scalarmult_SCALARBYTES],
             const uint8_t Ip[crypto_scalarmult_BYTES],
             const uint8_t Ep[crypto_scalarmult_BYTES]) {
  uint8_t sec[crypto_scalarmult_BYTES * 3], *ptr = sec;
  sodium_mlock(sec, sizeof sec);

  if(0!=crypto_scalarmult(ptr,ex,Ip)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ix,Ep)) return 1;
  ptr+=crypto_scalarmult_BYTES;
  if(0!=crypto_scalarmult(ptr,ex,Ep)) return 1;
#ifdef TRACE
  dump(sec, 96, "sec");
#endif

  // and hash for the result SK = f_K(0)
  derive_secret(mk, sec);
  sodium_munlock(sec,sizeof(sec));
  return 0;
}

int sphinx_blindPW(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  // sets α := (H^0(pw))^r
  // hash x with H^0
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  sodium_mlock(h0,sizeof h0);
  crypto_generichash(h0, sizeof h0, pw, pwlen, 0, 0);
#ifdef TRACE
  dump(h0, 32, "h0");
#endif
  unsigned char H0[crypto_core_ristretto255_BYTES];
  sodium_mlock(H0,sizeof H0);
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);
#ifdef TRACE
  dump(H0,sizeof H0, "H0 ");
#endif
  // U picks r
  crypto_core_ristretto255_scalar_random(r);
#ifdef TRACE
  dump(r, 32, "r");
#endif
  // H^0(pw)^r
  if (crypto_scalarmult_ristretto255(alpha, r, H0) != 0) {
    sodium_munlock(H0,sizeof H0);
    return -1;
  }
  sodium_munlock(H0,sizeof H0);
#ifdef TRACE
  dump(alpha, 32, "alpha");
#endif
  return 0;
}

void sphinx_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res) {
  // hash for the result res = f_k(val)
  uint8_t v[32];
  memset(v,val,32);
  crypto_generichash(res, crypto_core_ristretto255_BYTES,  // output
                     v, sizeof v,                     // msg
                     k, k_len);                       // key
#ifdef TRACE
  dump(k, k_len, "k ");
  dump(&val, 1, "val ");
  dump(v, 32, "v ");
  dump(res, crypto_core_ristretto255_BYTES, "res ");
#endif
}
