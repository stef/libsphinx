/*
    @copyright 2018, pitchfork@ctrlc.hu
    This file is part of pitchforked sphinx.

    pitchforked sphinx is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    pitchfork is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with pitchforked sphinx. If not, see <http://www.gnu.org/licenses/>.

    This file implements the Opaque protocol
    as specified on page 28 of: https://eprint.iacr.org/2018/163
    with following deviations:
       1/ instead of HMQV it implements a Triple-DH instead - TODO/FIXME
       2/ it implements "user iterated hashing" from page 29 of the paper
       3/ implements a variant where U secrets never hit S unprotected
*/

//#define TRACE 1

#include <stdint.h>
#include <string.h>
#include "decaf.h"
#include <crypto_generichash.h>
#include <crypto_pwhash.h>
#ifndef TRACE
#include <randombytes.h>
#endif
#include <sodium/utils.h>
#include "opaque.h"

#ifdef TRACE
#include <stdio.h>

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  int i;
  printf("%s",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

static void randombytes(unsigned char* buf, size_t len) {
  memset(buf,0xa,len);
}
#endif

typedef struct {
  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  uint8_t p_u[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t extra_or_mac[crypto_secretbox_MACBYTES];
} __attribute((packed)) Opaque_Blob;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[DECAF_255_SCALAR_BYTES];
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  uint64_t extra_len;
  Opaque_Blob c;
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
  uint8_t auth[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  uint64_t extra_len;
  Opaque_Blob c;
} __attribute((packed)) Opaque_ServerSession;

typedef struct {
  uint8_t beta[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
} __attribute((packed)) Opaque_RegisterPub;

typedef struct {
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t k_s[DECAF_X25519_PRIVATE_BYTES];
} __attribute((packed)) Opaque_RegisterSec;

static void oprf(const uint8_t *x, const size_t x_len, const uint8_t *k, uint8_t *res) {
  // F_k(x) = H(x, (H0(x))^k) for key k ∈ Z_q

  // hash x with H0
  uint8_t h0[32];
  crypto_generichash(h0, sizeof h0, x, x_len, 0, 0);
  decaf_255_point_t H0;
  decaf_255_point_from_hash_nonuniform(H0, h0);

  // k -> Z_q
  decaf_255_scalar_t K;
  decaf_255_scalar_decode_long(K, k, DECAF_255_SCALAR_BYTES);

  // H0 ^ k
  decaf_255_point_t H0_k;
  decaf_255_point_scalarmul(H0_k, H0, K);
  decaf_255_scalar_destroy(K);
  decaf_255_point_destroy(H0);

  // h0 := (H0(x))^k
  decaf_255_point_encode(h0, H0_k);
  decaf_255_point_destroy(H0_k);

  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, x, x_len);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, res, 32);
  decaf_bzero(&state, sizeof(state));
  decaf_bzero(h0, sizeof(h0));
}

void opaque_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res) {
  // hash for the result res = f_k(val)
  uint8_t v[32];
  memset(v,val,32);
  crypto_generichash(res, DECAF_X25519_PUBLIC_BYTES,  // output
                     v, sizeof v,                     // msg
                     k, k_len);                       // key
#ifdef TRACE
  dump(k, k_len, "k ");
  dump(&val, 1, "val ");
  dump(v, 32, "v ");
  dump(res, DECAF_X25519_PUBLIC_BYTES, "res ");
#endif
}

// (StorePwdFile, sid , U, pw): S computes k_s ←_R Z_q , rw := F_k_s (pw),
// p_s ←_R Z_q , p_u ←_R Z_q , P_s := g^p_s , P_u := g^p_u , c ← AuthEnc_rw (p_u, P_u, P_s);
// it records file[sid ] := {k_s, p_s, P_s, P_u, c}.
int opaque_init_srv(const uint8_t *pw, const size_t pwlen, const unsigned char *extra, const uint64_t extra_len, unsigned char _rec[OPAQUE_USER_RECORD_LEN]) {
  Opaque_UserRecord *rec = (Opaque_UserRecord *)_rec;
#ifdef TRACE
  memset(_rec,0,sizeof(Opaque_UserRecord)+extra_len);
#endif

  // k_s ←_R Z_q
  randombytes(rec->k_s, 32);

  // rw := F_k_s (pw),
  uint8_t rw[32];
  oprf(pw, pwlen, rec->k_s, rw);

#ifdef TRACE
  dump((uint8_t*) rw, 32, "rw ");
#endif

  randombytes(rec->salt, sizeof(rec->salt));
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, rec->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    return 1;
  }

#ifdef TRACE
  dump((uint8_t*) rw, 32, "key ");
#endif

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // p_s ←_R Z_q
  randombytes(rec->p_s, DECAF_X25519_PRIVATE_BYTES); // random server secret key */

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // p_u ←_R Z_q
  randombytes(rec->c.p_u, DECAF_X25519_PRIVATE_BYTES); // random user secret key */

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // P_s := g^p_s
  decaf_x25519_derive_public_key(rec->P_s, rec->p_s);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // P_u := g^p_u
  decaf_x25519_derive_public_key(rec->P_u, rec->c.p_u);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // copy Pubkeys also into rec.c
  memcpy(rec->c.P_u, rec->P_u,DECAF_X25519_PUBLIC_BYTES*2);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  rec->extra_len = extra_len;
  // copy extra data into rec.c
  if(extra_len)
     memcpy(rec->c.extra_or_mac, extra, extra_len);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // c ← AuthEnc_rw(p_u,P_u,P_s);
  randombytes(rec->c.nonce, crypto_secretbox_NONCEBYTES);                                  // nonce for crypto_secretbox

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif

  crypto_secretbox_easy(((uint8_t*)&rec->c)+crypto_secretbox_NONCEBYTES,                   // ciphertext
                        ((uint8_t*)&rec->c)+crypto_secretbox_NONCEBYTES,                   // plaintext
                        DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PUBLIC_BYTES*2+extra_len,  // plaintext len
                        ((uint8_t*)&rec->c),                                               // nonce
                        rw);                                                               // key

  decaf_bzero(rw, sizeof(rw));

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "cipher user rec ");
#endif
  return 0;
}

static void blindPW(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  // U picks r
  randombytes(r, DECAF_X25519_PRIVATE_BYTES);

  // sets α := (H^0(pw))^r
  uint8_t h0[32];
  crypto_generichash(h0, sizeof h0, pw, pwlen, 0, 0);
  decaf_255_point_t H0;
  decaf_255_point_from_hash_nonuniform(H0, h0);
  decaf_bzero(h0, sizeof(h0));
  decaf_255_scalar_t R;
  decaf_255_scalar_decode_long(R, r, 32);
  decaf_255_point_scalarmul(H0, H0, R);
  decaf_255_scalar_destroy(R);
  decaf_255_point_encode(alpha, H0);
  decaf_255_point_destroy(H0);
}

//(UsrSession, sid , ssid , S, pw): U picks r, x_u ←_R Z_q ; sets α := (H^0(pw))^r and
//X_u := g^x_u ; sends α and X_u to S.
void opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, unsigned char _sec[OPAQUE_USER_SESSION_SECRET_LEN], unsigned char _pub[OPAQUE_USER_SESSION_PUBLIC_LEN]) {
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret*) _sec;
  Opaque_UserSession *pub = (Opaque_UserSession*) _pub;

  blindPW(pw, pwlen, sec->r, pub->alpha);
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif

  // x_u ←_R Z_q
  randombytes(sec->x_u, DECAF_X25519_PRIVATE_BYTES);

  // X_u := g^x_u
  decaf_x25519_derive_public_key(pub->X_u, sec->x_u);
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
}

static void derive_secret(uint8_t *mk, const uint8_t *sec) {
  // workaround hash sec from 96 bytes down to 64,
  // as blake can only handle 64 as a key
  uint8_t hashkey[64];
  crypto_generichash(hashkey, sizeof hashkey, sec, 96, 0, 0);

  // and hash for the result SK = f_K(0)
  opaque_f(hashkey, sizeof hashkey, 0, mk);

  decaf_bzero(hashkey, sizeof(hashkey));
}

// implements server end of triple-dh
static int server_kex(uint8_t *mk, const uint8_t ix[32], const uint8_t ex[32], const uint8_t Ip[32], const uint8_t Ep[32]) {
  uint8_t sec[DECAF_X25519_PUBLIC_BYTES * 3], *ptr = sec;

  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ep,ix)) return 1;
  ptr+=DECAF_X25519_PUBLIC_BYTES;
  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ip,ex)) return 1;
  ptr+=DECAF_X25519_PUBLIC_BYTES;
  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ep,ex)) return 1;

  derive_secret(mk, sec);

  decaf_bzero(sec,sizeof(sec));
  return 0;
}

// 2. (SvrSession, sid , ssid ): On input α from U, S proceeds as follows:
// (a) Checks that α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
// (c) Picks x_s ←_R Z_q and computes β := α^k_s and X_s := g^x_s ;
// (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f K (0);
// (e) Sends β, X s and c to U;
// (f) Outputs (sid , ssid , SK).
int opaque_session_srv(const unsigned char _pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const unsigned char _rec[OPAQUE_USER_RECORD_LEN], unsigned char _resp[OPAQUE_SERVER_SESSION_LEN], uint8_t *sk) {
  Opaque_UserSession *pub = (Opaque_UserSession *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;

  decaf_255_point_t Alpha;
  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Alpha, pub->alpha, DECAF_FALSE)) return 1;

  // (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
  // provided as parameter rec

  // (c) Picks x_s ←_R Z_q
  uint8_t x_s[DECAF_X25519_PRIVATE_BYTES];
  randombytes(x_s, DECAF_X25519_PRIVATE_BYTES);

  // computes β := α^k_s
  decaf_255_point_t Beta;
  decaf_255_scalar_t K_s;
  decaf_255_scalar_decode_long(K_s, rec->k_s, 32);
  decaf_255_point_scalarmul(Beta, Alpha, K_s);
  decaf_255_point_destroy(Alpha);
  decaf_255_scalar_destroy(K_s);
  decaf_255_point_encode(resp->beta, Beta);
  decaf_255_point_destroy(Beta);

  // X_s := g^x_s;
  decaf_x25519_derive_public_key(resp->X_s, x_s);

  // (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f_K(0);
  // paper instantiates HMQV, we do only triple-dh
  if(0!=server_kex(sk, rec->p_s, x_s, rec->P_u, pub->X_u)) return 1;
  decaf_bzero(x_s, sizeof(x_s));

  // (e) Sends β, X_s and c to U;
  memcpy(&resp->c, &rec->c, sizeof rec->c + rec->extra_len);
  // also send salt
  memcpy(&resp->salt, &rec->salt, sizeof rec->salt);
  // also send len of extra data
  memcpy(&resp->extra_len, &rec->extra_len, sizeof rec->extra_len);

  opaque_f(sk, sizeof sk, 1, resp->auth);

  // (f) Outputs (sid , ssid , SK).
  // e&f handled as parameters

#ifdef TRACE
  dump(_resp,OPAQUE_SERVER_SESSION_LEN+rec->extra_len, "resp ");
#endif

  return 0;
}

// implements user end of triple-dh
static int user_kex(uint8_t *mk, const uint8_t ix[32], const uint8_t ex[32], const uint8_t Ip[32], const uint8_t Ep[32]) {
  uint8_t sec[DECAF_X25519_PUBLIC_BYTES * 3], *ptr = sec;

  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ip,ex)) return 1;
  ptr+=DECAF_X25519_PUBLIC_BYTES;
  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ep,ix)) return 1;
  ptr+=DECAF_X25519_PUBLIC_BYTES;
  if(DECAF_SUCCESS!=decaf_x25519(ptr,Ep,ex)) return 1;

  // and hash for the result SK = f_K(0)
  derive_secret(mk, sec);
  decaf_bzero(sec,sizeof(sec));
  return 0;
}

// 3. On β, X_s and c from S, U proceeds as follows:
// (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
// (b) Computes rw := H(pw, β^1/r );
// (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
//     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
// (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
// (e) Outputs (sid, ssid, SK).
int opaque_session_usr_finish(const uint8_t *pw, const size_t pwlen, const unsigned char _resp[OPAQUE_SERVER_SESSION_LEN], const unsigned char _sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t *sk, uint8_t *extra, uint8_t rwd[crypto_secretbox_KEYBYTES]) {
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret *) _sec;

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  decaf_255_point_t Beta;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Beta, resp->beta, DECAF_FALSE)) return 1;

  // (b) Computes rw := H(pw, β^1/r );
  decaf_255_scalar_t r;
  decaf_255_scalar_decode_long(r, sec->r, 32);
  // r = 1/r
  if(decaf_255_scalar_invert(r, r)!=DECAF_SUCCESS) return 1;

  // H0 = β^(1/r)
  decaf_255_point_t H0;
  decaf_255_point_scalarmul(H0, Beta, r);
  decaf_255_scalar_destroy(r);
  decaf_255_point_destroy(Beta);
  uint8_t h0[32], rw[crypto_secretbox_KEYBYTES];
  decaf_255_point_encode(h0, H0);
  decaf_255_point_destroy(H0);

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, rw, 32);
  decaf_bzero(h0, sizeof(h0));
  decaf_bzero(&state, sizeof(state));

  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, resp->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    return 1;
  }

  // (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
  //     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
  if(OPAQUE_BLOB_LEN+resp->extra_len < OPAQUE_BLOB_LEN) return 1; // check integer overflow
  uint8_t buf[OPAQUE_BLOB_LEN+resp->extra_len];
  Opaque_Blob *c = (Opaque_Blob *) buf;
  if(0!=crypto_secretbox_open_easy(buf+crypto_secretbox_NONCEBYTES,                     // plaintext
                                   ((uint8_t*)&resp->c)+crypto_secretbox_NONCEBYTES,    // ciphertext
                                                                                        // plaintext len
                                   DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PUBLIC_BYTES*2+crypto_secretbox_MACBYTES+resp->extra_len,
                                   ((uint8_t*)&resp->c),                                // nonce
                                   rw)) {                                               // key
    decaf_bzero(rw, sizeof(rw));
    return 1;
  }
  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*) "rwd", 3);
  decaf_bzero(rw, sizeof(rw));

  // (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
  if(0!=user_kex(sk, c->p_u, sec->x_u, c->P_s, resp->X_s)) {
    decaf_bzero(buf, sizeof(buf));
    decaf_bzero(rw, sizeof(rw));
    return 1;
  }

  uint8_t auth[32];
  opaque_f(sk, sizeof sk, 1, auth);
  if(0!=sodium_memcmp(auth,resp->auth,32)) {
    if(rwd!=NULL) decaf_bzero(rwd, crypto_secretbox_KEYBYTES);
    return 1;
  }

  // copy out extra
  if(resp->extra_len)
     memcpy(extra, c->extra_or_mac, resp->extra_len);

  decaf_bzero(buf, sizeof(buf));

  // (e) Outputs (sid, ssid, SK).

  return 0;
}

// variant where the secrets of U never touch S unencrypted

// U computes: blinded PW
void opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  blindPW(pw, pwlen, r, alpha);
}

// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
int opaque_private_init_srv_respond(const uint8_t *alpha, unsigned char _sec[OPAQUE_REGISTER_SECRET_LEN], unsigned char _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSec *sec = (Opaque_RegisterSec *) _sec;
  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;

  decaf_255_point_t Alpha;
  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Alpha, alpha, DECAF_FALSE)) return 1;

  // k_s ←_R Z_q
  randombytes(sec->k_s, DECAF_X25519_PRIVATE_BYTES);  // random server user key */

  // computes β := α^k_s
  decaf_255_point_t Beta;
  decaf_255_scalar_t K_s;
  decaf_255_scalar_decode_long(K_s, sec->k_s, 32);
  decaf_255_point_scalarmul(Beta, Alpha, K_s);
  decaf_255_point_destroy(Alpha);
  decaf_255_scalar_destroy(K_s);
  decaf_255_point_encode(pub->beta, Beta);
  decaf_255_point_destroy(Beta);

  // p_s ←_R Z_q
  randombytes(sec->p_s, DECAF_X25519_PRIVATE_BYTES); // random server long-term key */

  // P_s := g^p_s
  decaf_x25519_derive_public_key(pub->P_s, sec->p_s);

  return 0;
}

// user computes:
// (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
// (b) Computes rw := H(pw, β^1/r );
// (c) generates salt
// (c) p_u ←_R Z_q
// (d) P_u := g^p_u,
// (e) c ← AuthEnc_rw (p_u, P_u, P_s);
int opaque_private_init_usr_respond(const uint8_t *pw, const size_t pwlen, const uint8_t *r, const unsigned char _pub[OPAQUE_REGISTER_PUBLIC_LEN], const unsigned char *extra, const uint64_t extra_len, unsigned char _rec[OPAQUE_USER_RECORD_LEN], uint8_t rwd[crypto_secretbox_KEYBYTES]) {

  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;
#ifdef TRACE
  memset(_rec,0,sizeof(Opaque_UserRecord)+extra_len);
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  decaf_255_point_t Beta;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Beta, pub->beta, DECAF_FALSE)) return 1;

  // (b) Computes rw := H(pw, β^1/r );
  decaf_255_scalar_t R;
  decaf_255_scalar_decode_long(R, r, 32);
  // r = 1/r
  if(decaf_255_scalar_invert(R, R)!=DECAF_SUCCESS) return 1;

  // H0 = β^(1/r)
  decaf_255_point_t H0;
  decaf_255_point_scalarmul(H0, Beta, R);
  decaf_255_scalar_destroy(R);
  decaf_255_point_destroy(Beta);
  uint8_t h0[32], rw[32];
  decaf_255_point_encode(h0, H0);
  decaf_255_point_destroy(H0);

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, rw, 32);
  decaf_bzero(h0, sizeof(h0));
  decaf_bzero(&state, sizeof(state));

#ifdef TRACE
  dump((uint8_t*) rw, 32, "rw ");
#endif

  // generate salt
  randombytes(rec->salt, sizeof(rec->salt));

  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, rec->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    return 1;
  }

#ifdef TRACE
  dump((uint8_t*) rw, 32, "key ");
#endif

  // p_u ←_R Z_q
  randombytes(rec->c.p_u, DECAF_X25519_PRIVATE_BYTES); // random user secret key */

  // P_u := g^p_u
  decaf_x25519_derive_public_key(rec->c.P_u, rec->c.p_u);

  // copy P_u also into plaintext rec */
  memcpy(rec->P_u, rec->c.P_u,DECAF_X25519_PUBLIC_BYTES);

  // copy P_s into rec.c
  memcpy(rec->c.P_s, pub->P_s,DECAF_X25519_PUBLIC_BYTES);

  // copy extra data into rec.c
  rec->extra_len = extra_len;
     memcpy(rec->c.extra_or_mac, extra, extra_len);
  if(extra_len)
     memcpy(rec->c.extra_or_mac, extra, extra_len);

  // c ← AuthEnc_rw(p_u,P_u,P_s);
  randombytes(rec->c.nonce, crypto_secretbox_NONCEBYTES);                                  // nonce for crypto_secretbox

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif

  crypto_secretbox_easy(((uint8_t*)&rec->c)+crypto_secretbox_NONCEBYTES,                   // ciphertext
                        ((uint8_t*)&rec->c)+crypto_secretbox_NONCEBYTES,                   // plaintext
                        DECAF_X25519_PRIVATE_BYTES+DECAF_X25519_PUBLIC_BYTES*2+extra_len,  // plaintext len
                        ((uint8_t*)&rec->c),                                               // nonce
                        rw);                                                               // key
#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "cipher user rec ");
#endif

  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*)"rwd", 3);
  decaf_bzero(rw, sizeof(rw));

  return 0;
}

// S records file[sid ] := {k_s, p_s, P_s, P_u, c}.
void opaque_private_init_srv_finish(const unsigned char _sec[OPAQUE_REGISTER_SECRET_LEN], const unsigned char _pub[OPAQUE_REGISTER_PUBLIC_LEN], unsigned char _rec[OPAQUE_USER_RECORD_LEN]) {
  Opaque_RegisterSec *sec = (Opaque_RegisterSec *) _sec;
  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  memcpy(rec->k_s, sec->k_s, sizeof rec->k_s);
  memcpy(rec->p_s, sec->p_s, sizeof rec->p_s);
  memcpy(rec->P_s, pub->P_s, sizeof rec->P_s);
#ifdef TRACE
  dump((uint8_t*) rec, sizeof(Opaque_UserRecord)+rec->extra_len, "user rec ");
#endif
}
