/*
    @copyright 2018-19, pitchfork@ctrlc.hu
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
       1/ instead of HMQV it implements a Triple-DH instead
       2/ it implements "user iterated hashing" from page 29 of the paper
       3/ implements a variant where U secrets never hit S unprotected
       4/ it allows to store extra data in the encrypted blob stored by
          the opaque server
*/

#include "opaque.h"
#include "common.h"

typedef struct {
  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  uint8_t p_u[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
  uint8_t extra_or_mac[crypto_secretbox_MACBYTES];
} __attribute((packed)) Opaque_Blob;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
  uint8_t salt[32];
  uint64_t extra_len;
  Opaque_Blob c;
} __attribute((packed)) Opaque_UserRecord;

// data sent to S from U in login#1
typedef struct {
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t x_u[crypto_scalarmult_SCALARBYTES];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t X_s[crypto_scalarmult_BYTES];
  uint8_t auth[crypto_generichash_BYTES];
  uint8_t salt[32];
  uint64_t extra_len;
  Opaque_Blob c;
} __attribute((packed)) Opaque_ServerSession;

typedef struct {
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
} __attribute((packed)) Opaque_RegisterPub;

typedef struct {
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
} __attribute((packed)) Opaque_RegisterSec;

// (StorePwdFile, sid , U, pw): S computes k_s ←_R Z_q , rw := F_k_s (pw),
// p_s ←_R Z_q , p_u ←_R Z_q , P_s := g^p_s , P_u := g^p_u , c ← AuthEnc_rw (p_u, P_u, P_s);
// it records file[sid ] := {k_s, p_s, P_s, P_u, c}.
int opaque_init_srv(const uint8_t *pw, const size_t pwlen, const unsigned char *extra, const uint64_t extra_len, unsigned char _rec[OPAQUE_USER_RECORD_LEN]) {
  Opaque_UserRecord *rec = (Opaque_UserRecord *)_rec;

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(rec->k_s);

  // rw := F_k_s (pw),
  uint8_t rw[32];
  sodium_mlock(rw,sizeof rw);
  if(sphinx_oprf(pw, pwlen, rec->k_s, rw)!=0) return -1;

#ifdef TRACE
  dump((uint8_t*) rw, 32, "rw ");
#endif

  randombytes(rec->salt, sizeof(rec->salt));
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, rec->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw,sizeof rw);
    return -1;
  }

#ifdef TRACE
  dump((uint8_t*) rw, 32, "key ");
#endif

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // p_s ←_R Z_q
  randombytes(rec->p_s, crypto_scalarmult_SCALARBYTES); // random server secret key

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // p_u ←_R Z_q
  randombytes(rec->c.p_u, crypto_scalarmult_SCALARBYTES); // random user secret key

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // P_s := g^p_s
  crypto_scalarmult_base(rec->P_s, rec->p_s);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // P_u := g^p_u
  crypto_scalarmult_base(rec->P_u, rec->c.p_u);

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "plain user rec ");
#endif
  // copy Pubkeys also into rec.c
  memcpy(rec->c.P_u, rec->P_u,crypto_scalarmult_BYTES*2);

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
                        crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES*2+extra_len, // plaintext len
                        ((uint8_t*)&rec->c),                                               // nonce
                        rw);                                                               // key

  sodium_munlock(rw, sizeof(rw));

#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "cipher user rec ");
#endif
  return 0;
}

//(UsrSession, sid , ssid , S, pw): U picks r, x_u ←_R Z_q ; sets α := (H^0(pw))^r and
//X_u := g^x_u ; sends α and X_u to S.
int opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, unsigned char _sec[OPAQUE_USER_SESSION_SECRET_LEN], unsigned char _pub[OPAQUE_USER_SESSION_PUBLIC_LEN]) {
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret*) _sec;
  Opaque_UserSession *pub = (Opaque_UserSession*) _pub;

  if(0!=sphinx_blindPW(pw, pwlen, sec->r, pub->alpha)) return -1;
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif

  // x_u ←_R Z_q
  randombytes(sec->x_u, crypto_scalarmult_SCALARBYTES);

  // X_u := g^x_u
  crypto_scalarmult_base(pub->X_u, sec->x_u);
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
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

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(pub->alpha)!=1) return -1;

  // (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
  // provided as parameter rec

  // (c) Picks x_s ←_R Z_q
  uint8_t x_s[crypto_scalarmult_SCALARBYTES];
  sodium_mlock(x_s,sizeof x_s);
  randombytes(x_s, crypto_scalarmult_SCALARBYTES);

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(resp->beta, rec->k_s, pub->alpha) != 0) {
    return -1;
  }

  // X_s := g^x_s;
  crypto_scalarmult_base(resp->X_s, x_s);

  // (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f_K(0);
  // paper instantiates HMQV, we do only triple-dh
  if(0!=sphinx_server_3dh(sk, rec->p_s, x_s, rec->P_u, pub->X_u)) return -1;
  sodium_munlock(x_s, sizeof(x_s));

  // (e) Sends β, X_s and c to U;
  memcpy(&resp->c, &rec->c, sizeof rec->c + rec->extra_len);
  // also send salt
  memcpy(&resp->salt, &rec->salt, sizeof rec->salt);
  // also send len of extra data
  memcpy(&resp->extra_len, &rec->extra_len, sizeof rec->extra_len);

  sphinx_f(sk, sizeof sk, 1, resp->auth);

  // (f) Outputs (sid , ssid , SK).
  // e&f handled as parameters

#ifdef TRACE
  dump(_resp,OPAQUE_SERVER_SESSION_LEN+rec->extra_len, "resp ");
#endif

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
  if(crypto_core_ristretto255_is_valid_point(resp->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // r = 1/r
  unsigned char ir[crypto_core_ristretto255_SCALARBYTES];
  sodium_mlock(ir,sizeof ir);
  if (crypto_core_ristretto255_scalar_invert(ir, sec->r) != 0) {
    return -1;
  }

  // h0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  unsigned char h0[crypto_core_ristretto255_BYTES];
  sodium_mlock(h0,sizeof h0);
  if (crypto_scalarmult_ristretto255(h0, ir, resp->beta) != 0) {
    return -1;
  }
  sodium_munlock(ir,sizeof ir);
  uint8_t rw[crypto_secretbox_KEYBYTES];
  sodium_mlock(rw,sizeof rw);

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  sodium_mlock(&state,sizeof state);
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, rw, 32);
  sodium_munlock(h0, sizeof(h0));
  sodium_munlock(&state, sizeof(state));

  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, resp->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw, sizeof rw);
    return -1;
  }

  // (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
  //     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
  if(resp->extra_len > OPAQUE_MAX_EXTRA_BYTES) return -1; // check integer overflow
  uint8_t buf[OPAQUE_BLOB_LEN+resp->extra_len];
  sodium_mlock(buf,sizeof buf);
  Opaque_Blob *c = (Opaque_Blob *) buf;
  if(0!=crypto_secretbox_open_easy(buf+crypto_secretbox_NONCEBYTES,                     // plaintext
                                   ((uint8_t*)&resp->c)+crypto_secretbox_NONCEBYTES,    // ciphertext
                                                                                        // plaintext len
                                   crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES*2+crypto_secretbox_MACBYTES+resp->extra_len,
                                   ((uint8_t*)&resp->c),                                // nonce
                                   rw)) {                                               // key
    sodium_munlock(rw, sizeof(rw));
    sodium_munlock(buf,sizeof buf);
    return -1;
  }
  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*) "rwd", 3);
  sodium_munlock(rw, sizeof(rw));

  // (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
  if(0!=sphinx_user_3dh(sk, c->p_u, sec->x_u, c->P_s, resp->X_s)) {
    sodium_munlock(buf, sizeof(buf));
    return -1;
  }

  uint8_t auth[crypto_generichash_BYTES];
  sodium_mlock(auth, sizeof auth);
  sphinx_f(sk, sizeof sk, 1, auth);
  if(0!=sodium_memcmp(auth,resp->auth,crypto_generichash_BYTES)) {
    sodium_munlock(auth, sizeof auth);
    if(rwd!=NULL) sodium_munlock(rwd, crypto_secretbox_KEYBYTES);
    return -1;
  }
  sodium_munlock(auth, sizeof auth);

  // copy out extra
  if(resp->extra_len)
     memcpy(extra, c->extra_or_mac, resp->extra_len);

  sodium_munlock(buf, sizeof(buf));

  // (e) Outputs (sid, ssid, SK).

  return 0;
}

// variant where the secrets of U never touch S unencrypted

// U computes: blinded PW
int opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  return sphinx_blindPW(pw, pwlen, r, alpha);
}

// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
int opaque_private_init_srv_respond(const uint8_t *alpha, unsigned char _sec[OPAQUE_REGISTER_SECRET_LEN], unsigned char _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
  Opaque_RegisterSec *sec = (Opaque_RegisterSec *) _sec;
  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(alpha)!=1) return -1;

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(sec->k_s);

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(pub->beta, sec->k_s, alpha) != 0) {
    return -1;
  }

  // p_s ←_R Z_q
  randombytes(sec->p_s, crypto_scalarmult_SCALARBYTES); // random server long-term key

  // P_s := g^p_s
  crypto_scalarmult_base(pub->P_s, sec->p_s);

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
  if(crypto_core_ristretto255_is_valid_point(pub->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // invert r = 1/r
  unsigned char ir[crypto_core_ristretto255_SCALARBYTES];
  sodium_mlock(ir, sizeof ir);
  if (crypto_core_ristretto255_scalar_invert(ir, r) != 0) {
    return -1;
  }

  // H0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  unsigned char h0[crypto_core_ristretto255_BYTES];
  sodium_mlock(h0,sizeof h0);
  if (crypto_scalarmult_ristretto255(h0, ir, pub->beta) != 0) {
    return -1;
  }
  sodium_munlock(ir, sizeof ir);
  uint8_t rw[32];
  sodium_mlock(rw, sizeof rw);

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  sodium_mlock(&state, sizeof state);
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, rw, 32);
  sodium_munlock(h0, sizeof(h0));
  sodium_munlock(&state, sizeof(state));

#ifdef TRACE
  dump((uint8_t*) rw, 32, "rw ");
#endif

  // generate salt
  randombytes(rec->salt, sizeof(rec->salt));

  if (crypto_pwhash(rw, sizeof rw, (const char*) rw, sizeof rw, rec->salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw, sizeof(rw));
    return -1;
  }

#ifdef TRACE
  dump((uint8_t*) rw, 32, "key ");
#endif

  // p_u ←_R Z_q
  randombytes(rec->c.p_u, crypto_scalarmult_SCALARBYTES); // random user secret key

  // P_u := g^p_u
  crypto_scalarmult_base(rec->c.P_u, rec->c.p_u);

  // copy P_u also into plaintext rec
  memcpy(rec->P_u, rec->c.P_u,crypto_scalarmult_BYTES);

  // copy P_s into rec.c
  memcpy(rec->c.P_s, pub->P_s,crypto_scalarmult_BYTES);

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
                        crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES*2+extra_len, // plaintext len
                        ((uint8_t*)&rec->c),                                               // nonce
                        rw);                                                               // key
#ifdef TRACE
  dump(_rec, sizeof(Opaque_UserRecord)+extra_len, "cipher user rec ");
#endif

  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*)"rwd", 3);
  sodium_munlock(rw, sizeof(rw));

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
