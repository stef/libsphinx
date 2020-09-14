/*
    @copyright 2018-20, pitchfork@ctrlc.hu
    This file is part of pitchforked sphinx.

    libsphinx is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libsphinx is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libsphinx. If not, see <http://www.gnu.org/licenses/>.

    This file implements the Opaque protocol
    as specified on page 28 of: https://eprint.iacr.org/2018/163
    with following deviations:
       1/ instead of HMQV it implements a Triple-DH instead
       2/ it implements "user iterated hashing" from page 29 of the paper
       3/ implements a variant where U secrets never hit S unprotected

    TODO:
          - one master p_s/P_s for all users instead of / user server keypairs
          - p_u derived from rwd and thus also P_u
*/

#include "opaque.h"
#include "common.h"

#ifndef HAVE_SODIUM_HKDF
#include "aux/crypto_kdf_hkdf_sha256.h"
#endif

typedef struct {
  uint8_t nonce[crypto_hash_sha256_BYTES];
  uint16_t SecEnv_len;
  uint8_t p_u[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
  uint16_t ClrEnv_len;
  uint8_t mac[crypto_hash_sha256_BYTES];
} __attribute((packed)) Opaque_Blob;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[crypto_core_ristretto255_SCALARBYTES];
  uint8_t p_s[crypto_scalarmult_SCALARBYTES];
  uint8_t P_u[crypto_scalarmult_BYTES];
  uint8_t P_s[crypto_scalarmult_BYTES];
  uint32_t env_len;
  Opaque_Blob c;
} __attribute((packed)) Opaque_UserRecord;

// data sent to S from U in login#1
typedef struct {
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  uint8_t x_u[crypto_scalarmult_SCALARBYTES];
  uint8_t nonceU[OPAQUE_NONCE_BYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t beta[crypto_core_ristretto255_BYTES];
  uint8_t X_s[crypto_scalarmult_BYTES];
  uint8_t nonceS[OPAQUE_NONCE_BYTES];
  uint8_t auth[crypto_auth_hmacsha256_BYTES];
  uint32_t env_len;
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

typedef struct {
  uint8_t sk[32];
  uint8_t km2[crypto_auth_hmacsha256_KEYBYTES];
  uint8_t km3[crypto_auth_hmacsha256_KEYBYTES];
  uint8_t ke2[32];
  uint8_t ke3[32];
} __attribute((packed)) Opaque_Keys;

// derive keys
// SK, Km2, Km3, Ke2, Ke3 = HKDF(salt=0, IKM, info, L)
static void derive_keys(Opaque_Keys* keys, const uint8_t *ikm, const char info[crypto_hash_sha256_BYTES]) {
  uint8_t prk[crypto_kdf_hkdf_sha256_KEYBYTES];
  sodium_mlock(prk, sizeof prk);
  // SK, Km2, Km3, Ke2, Ke3 = HKDF(salt=0, IKM, info, L)
  crypto_kdf_hkdf_sha256_extract(prk, NULL, 0, ikm, crypto_scalarmult_BYTES*3);
  crypto_kdf_hkdf_sha256_expand((uint8_t *) keys, sizeof(Opaque_Keys), info, crypto_hash_sha256_BYTES, prk);
  sodium_munlock(prk,sizeof(prk));
}

static void calc_info(char info[crypto_hash_sha256_BYTES],
                      const uint8_t nonceU[OPAQUE_NONCE_BYTES],
                      const uint8_t nonceS[OPAQUE_NONCE_BYTES],
                      const Opaque_Ids *ids) {
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

  crypto_hash_sha256_update(&state, nonceU, OPAQUE_NONCE_BYTES);
  crypto_hash_sha256_update(&state, nonceS, OPAQUE_NONCE_BYTES);
  if(ids->idU!=NULL) crypto_hash_sha256_update(&state, ids->idU, ids->idU_len);
  if(ids->idS!=NULL) crypto_hash_sha256_update(&state, ids->idS, ids->idS_len);

  crypto_hash_sha256_final(&state, (uint8_t *) info);
}

static void get_xcript(uint8_t xcript[crypto_hash_sha256_BYTES],
                       crypto_hash_sha256_state *xcript_state,
                       const uint8_t oprf1[crypto_core_ristretto255_BYTES],
                       const uint8_t nonceU[OPAQUE_NONCE_BYTES],
                       const uint8_t epubu[crypto_scalarmult_BYTES],
                       const uint8_t oprf2[crypto_core_ristretto255_BYTES],
                       const uint8_t *envu, const size_t envu_len,
                       const uint8_t nonceS[OPAQUE_NONCE_BYTES],
                       const uint8_t epubs[crypto_scalarmult_BYTES],
                       const Opaque_App_Infos *infos,
                       const int use_info3) {
  // OPRF1, nonceU, info1*, IdU*, ePubU, OPRF2, EnvU, nonceS, info2*, ePubS, Einfo2*, info3*, Einfo3*
  crypto_hash_sha256_state state;
  crypto_hash_sha256_init(&state);

#ifdef TRACE
  if(xcript_state!=NULL) dump((uint8_t*)xcript_state,sizeof state, "xcript_state ");
  else printf("no xcript_state\n");
  dump(oprf1,crypto_core_ristretto255_BYTES, "oprf1 ");
  dump(nonceU,OPAQUE_NONCE_BYTES,"nonceU ");
  dump(epubu,crypto_scalarmult_BYTES,"epubu ");
  dump(oprf2,crypto_core_ristretto255_BYTES,"oprf2 ");
  dump(envu, envu_len, "envu ");
  dump(nonceS,OPAQUE_NONCE_BYTES,"nonceS ");
  dump(epubs,crypto_scalarmult_BYTES,"epubs ");
  if(infos) dump( (uint8_t*) infos, sizeof(Opaque_App_Infos), "infos ");
  else printf("no infos\n");
#endif

  crypto_hash_sha256_update(&state, oprf1, crypto_core_ristretto255_BYTES);
  crypto_hash_sha256_update(&state, nonceU, OPAQUE_NONCE_BYTES);
  if(infos!=NULL && infos->info1!=NULL) crypto_hash_sha256_update(&state, infos->info1, infos->info1_len);
  crypto_hash_sha256_update(&state, epubu, crypto_scalarmult_BYTES);
  crypto_hash_sha256_update(&state, oprf2, crypto_core_ristretto255_BYTES);
  crypto_hash_sha256_update(&state, envu, envu_len);
  crypto_hash_sha256_update(&state, nonceS, OPAQUE_NONCE_BYTES);
  if(infos!=NULL && infos->info2!=NULL) crypto_hash_sha256_update(&state, infos->info2, infos->info2_len);
  crypto_hash_sha256_update(&state, epubs, crypto_scalarmult_BYTES);
  if(infos!=NULL) {
    if(infos->einfo2!=NULL) crypto_hash_sha256_update(&state, infos->einfo2, infos->einfo2_len);
    if(use_info3!=0) {
      if(infos->info3!=NULL) crypto_hash_sha256_update(&state, infos->info3, infos->info3_len);
      if(infos->einfo3!=NULL) crypto_hash_sha256_update(&state, infos->einfo3, infos->einfo3_len);
    }
  }

  // preserve xcript hash state for server so it does not have to
  // remember/recalc the xcript so far when authenticating the client
  if(xcript_state && (!infos || !(infos->einfo3 || infos->info3))) {
    memcpy(xcript_state, &state, sizeof state);
  }
  crypto_hash_sha256_final(&state, xcript);
#ifdef TRACE
  dump(xcript, crypto_hash_sha256_BYTES,"xcript ");
#endif
}

//opaque_session_srv
static void get_xcript_srv(uint8_t xcript[crypto_hash_sha256_BYTES],
                           const Opaque_UserSession *pub,
                           const Opaque_ServerSession *resp,
                           Opaque_ServerAuthCTX *ctx,
                           const Opaque_App_Infos *infos) {
  get_xcript(xcript, &ctx->xcript_state, pub->alpha, pub->nonceU, pub->X_u, resp->beta, (uint8_t*) &resp->c, resp->env_len, resp->nonceS, resp->X_s, infos, 0);
}
// session user finish
static void get_xcript_usr(uint8_t xcript[crypto_hash_sha256_BYTES],
                           const Opaque_UserSession_Secret *sec,
                           Opaque_ServerSession *resp,
                           const uint8_t *env,
                           const uint8_t X_u[crypto_scalarmult_BYTES],
                           const Opaque_App_Infos *infos,
                           const int use_info3) {
  get_xcript(xcript, 0, sec->alpha, sec->nonceU, X_u, resp->beta, env, resp->env_len, resp->nonceS, resp->X_s, infos, use_info3);
}


// implements server end of triple-dh
static int opaque_server_3dh(Opaque_Keys *keys,
               const uint8_t ix[crypto_scalarmult_SCALARBYTES],
               const uint8_t ex[crypto_scalarmult_SCALARBYTES],
               const uint8_t Ip[crypto_scalarmult_BYTES],
               const uint8_t Ep[crypto_scalarmult_BYTES],
               const char info[crypto_hash_sha256_BYTES]) {
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

  derive_keys(keys, sec, info);
#ifdef TRACE
  dump((uint8_t*) keys, sizeof(Opaque_Keys), "keys ");
#endif

  sodium_munlock(sec,sizeof(sec));
  return 0;
}

// implements user end of triple-dh
static int opaque_user_3dh(Opaque_Keys *keys,
             const uint8_t ix[crypto_scalarmult_SCALARBYTES],
             const uint8_t ex[crypto_scalarmult_SCALARBYTES],
             const uint8_t Ip[crypto_scalarmult_BYTES],
             const uint8_t Ep[crypto_scalarmult_BYTES],
             const char info[crypto_hash_sha256_BYTES]) {
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
  derive_keys(keys, sec, info);
#ifdef TRACE
  dump((uint8_t*) keys, sizeof(Opaque_Keys), "keys ");
#endif

  sodium_munlock(sec,sizeof(sec));
  return 0;
}

// enveloping function as specified in the ietf cfrg draft https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06#section-4
static int opaque_envelope(const uint8_t *rwd, const uint8_t *SecEnv, const size_t SecEnv_len,
                     const uint8_t *ClrEnv, const size_t ClrEnv_len,
                     uint8_t *envelope, // must be of size: OPAQUE_ENVELOPE_META_LEN + SecEnv_len+ClrEnv_len
                                        // len(nonce|uint16|SecEnv|uint16|ClrEnv|hmacTag)
                     uint8_t export_key[crypto_hash_sha256_BYTES]) {
  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope) return 1;
  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp,ClrEnv_len, &tmp)) return 1;
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv0 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv0 ");
#endif

  // (2) Set E = Nonce | ....
  randombytes(envelope,crypto_hash_sha256_BYTES);

  if(__builtin_add_overflow(2*crypto_hash_sha256_BYTES,SecEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  char ctx[crypto_hash_sha256_BYTES+9];
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  uint8_t pad[SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwd);

  uint8_t *c = envelope+crypto_hash_sha256_BYTES;

  if(SecEnv) {
    // set secenv_len prefix
    *((uint16_t*) c) = SecEnv_len;
    c+=2;

    //(1) Set C = SecEnv XOR PAD
    //(2) Set E = nonce | C | ...
    size_t i;
#ifdef TRACE
    dump(pad,SecEnv_len, "pad ");
    dump(c,SecEnv_len, "target ");
#endif
    for(i=0;i<SecEnv_len;i++) c[i]=SecEnv[i]^pad[i];
    c+=SecEnv_len;
  } else {
    *((uint16_t*) c) = 0;
    c+=2;
  }
  sodium_munlock(pad, sizeof pad);

  //(2) Set E = nonce | C | ClrEnv
  if(ClrEnv) {
    // set clrenv_len prefix
    *((uint16_t*) c) = ClrEnv_len;
    c+=2;
    memcpy(c, ClrEnv, ClrEnv_len);
    c+=ClrEnv_len;
  } else {
    *((uint16_t*) c) = 0;
    c+=2;
  }
#ifdef TRACE
  dump(SecEnv,SecEnv_len, "SecEnv1 ");
  dump(ClrEnv,ClrEnv_len, "ClrEnv1 ");
#endif

  // auth_key = HKDF-Expand(RwdU, concat(nonce, "AuthKey"), Nh)
  uint8_t auth_key[crypto_hash_sha256_BYTES];
  memcpy(ctx+crypto_hash_sha256_BYTES,"AuthKey",7);
  sodium_mlock(auth_key, sizeof auth_key);
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwd);
  //(3) Set T = HMAC(E,auth_key)
  const size_t env_len=crypto_hash_sha256_BYTES+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t);
#ifdef TRACE
  dump(envelope,env_len,"envelope auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
#endif
  crypto_auth_hmacsha256(envelope + env_len, // out
                         envelope,           // in
                         env_len,            // len(in)
                         auth_key);          // key
  sodium_munlock(auth_key, sizeof auth_key);
#ifdef TRACE
  dump(envelope+env_len, crypto_hash_sha256_BYTES, "auth tag ");
  dump(envelope,crypto_hash_sha256_BYTES*2+SecEnv_len+ClrEnv_len+2*sizeof(uint16_t), "envelope ");
#endif

  if(export_key) {
    // export_key = HKDF-Expand(RwdU, concat(nonce, "ExportKey"), Nh)
    memcpy(ctx+crypto_hash_sha256_BYTES,"ExportKey",9);
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwd);
#ifdef TRACE
    dump(export_key,crypto_hash_sha256_BYTES, "export_key ");
#endif
  }


  return 0;
}

static int opaque_envelope_open(const uint8_t *rwd, const uint8_t *envelope, const size_t env_len,
                         uint8_t *SecEnv, uint16_t *SecEnv_len,
                         uint8_t **ClrEnv, uint16_t *ClrEnv_len,
                         uint8_t export_key[crypto_hash_sha256_BYTES]) {

  if(((SecEnv==0) ^ (SecEnv_len==0)) || ((ClrEnv==0) ^ (ClrEnv_len==0)) || !rwd || !envelope || env_len < 2*crypto_hash_sha256_BYTES+2*sizeof(uint16_t)) return 1;

#ifdef TRACE
  dump(envelope,env_len, "open envelope ");
#endif

  // (1) verify authentication tag on the envelope
  // auth_key = HKDF-Expand(RwdU, concat(nonce, "AuthKey"), Nh)
  char ctx[crypto_hash_sha256_BYTES+9]; // reused also for pad and export key, hence bigger than needed
  memcpy(ctx,envelope,crypto_hash_sha256_BYTES);

  uint8_t auth_key[crypto_hash_sha256_BYTES];
  sodium_mlock(auth_key, sizeof auth_key);
  memcpy(ctx+crypto_hash_sha256_BYTES,"AuthKey",7);
  crypto_kdf_hkdf_sha256_expand(auth_key, sizeof auth_key, ctx, crypto_hash_sha256_BYTES+7, rwd);

  size_t tmp;
  if(__builtin_add_overflow((uintptr_t) envelope - crypto_hash_sha256_BYTES,env_len, &tmp)) return 1;

#ifdef TRACE
  dump(envelope,env_len-crypto_hash_sha256_BYTES,"envelope auth ");
  dump(auth_key,sizeof auth_key, "auth_key ");
  dump((uint8_t*) tmp,crypto_hash_sha256_BYTES, "auth tag ");
#endif
  if(-1 == crypto_auth_hmacsha256_verify((uint8_t*) tmp,                     // tag
                                         envelope,                           // in
                                         env_len-crypto_hash_sha256_BYTES,   // inlen
                                         auth_key)) {
    sodium_munlock(auth_key, sizeof auth_key);
    return 1;
  }
  sodium_munlock(auth_key, sizeof auth_key);

  // parse envelope for *env_len fields
  const uint8_t *ptr = envelope+crypto_hash_sha256_BYTES;
  uint16_t sl,cl;
  sl = *((uint16_t*) ptr);
  ptr += 2 + sl;
  cl = *((uint16_t*) (ptr));
  *SecEnv_len=sl;
  *ClrEnv_len=cl;
#ifdef TRACE
  printf("SecEnv_len: %d\nClrEnv_len: %d\n", sl, cl);
#endif
  // sanity check the two lengths, already authenticated by the hmac above, but make sure the sender is not some joker
  if(env_len != sl + cl + 2*sizeof(uint16_t) + 2*crypto_hash_sha256_BYTES) return 1;
  if(__builtin_add_overflow((uintptr_t) envelope + crypto_hash_sha256_BYTES+sizeof(uint16_t),*SecEnv_len, &tmp)) return 1;
  if(__builtin_add_overflow(tmp+sizeof(uint16_t),*ClrEnv_len, &tmp)) return 1;

  // pad = HKDF-Expand(RwdU, concat(nonce, "Pad"), len(pt))
  uint8_t pad[*SecEnv_len];
  sodium_mlock(pad, sizeof pad);
  memcpy(ctx+crypto_hash_sha256_BYTES,"Pad",3);
  crypto_kdf_hkdf_sha256_expand(pad, sizeof pad, ctx, crypto_hash_sha256_BYTES+3, rwd);
#ifdef TRACE
  dump(pad,sizeof pad, "pad ");
#endif

  const uint8_t *c = envelope+crypto_hash_sha256_BYTES+sizeof(uint16_t);
  // decrypt SecEnv
  if(SecEnv) {
    size_t i;
    for(i=0;i<*SecEnv_len;i++) SecEnv[i]=c[i]^pad[i];
    c+=*SecEnv_len;
  }
  sodium_munlock(pad, sizeof pad);

  // return ClrEnv
  c+=sizeof(uint16_t);
  if (ClrEnv) *ClrEnv=(uint8_t*)c;
#ifdef TRACE
  dump(SecEnv,*SecEnv_len, "SecEnv ");
  dump(*ClrEnv,*ClrEnv_len, "ClrEnv ");
#endif

  if(export_key) {
    // export_key = HKDF-Expand(RwdU, concat(nonce, "ExportKey"), Nh)
    memcpy(ctx+crypto_hash_sha256_BYTES,"ExportKey",9);
    crypto_kdf_hkdf_sha256_expand(export_key, crypto_hash_sha256_BYTES, ctx, crypto_hash_sha256_BYTES+9, rwd);
#ifdef TRACE
    dump(export_key,crypto_hash_sha256_BYTES, "export_key ");
#endif
  }
  return 0;
}

// (StorePwdFile, sid , U, pw): S computes k_s ←_R Z_q , rw := F_k_s (pw),
// p_s ←_R Z_q , p_u ←_R Z_q , P_s := g^p_s , P_u := g^p_u , c ← AuthEnc_rw (p_u, P_u, P_s);
// it records file[sid] := {k_s, p_s, P_s, P_u, c}.
int opaque_init_srv(const uint8_t *pw, const size_t pwlen,
                    const uint8_t *key, const uint64_t key_len,
                    const uint8_t *ClrEnv, const uint16_t ClrEnv_len,
                    uint8_t _rec[OPAQUE_USER_RECORD_LEN],
                    uint8_t export_key[crypto_hash_sha256_BYTES]) {
  Opaque_UserRecord *rec = (Opaque_UserRecord *)_rec;
#ifdef TRACE
  memset(_rec,0,OPAQUE_USER_RECORD_LEN+ClrEnv_len);
#endif

  // k_s ←_R Z_q
  crypto_core_ristretto255_scalar_random(rec->k_s);

  // rw := F_k_s (pw),
  uint8_t rw0[32];
  if(-1==sodium_mlock(rw0,sizeof rw0)) return -1;
  if(sphinx_oprf(pw, pwlen, rec->k_s, key, key_len, rw0)!=0) {
    sodium_munlock(rw0,sizeof rw0);
    return -1;
  }

#ifdef TRACE
  dump((uint8_t*) rw0, 32, "rw0 ");
#endif
  uint8_t rw[32];
  if(-1==sodium_mlock(rw,sizeof rw)) {
    sodium_munlock(rw0,sizeof rw0);
    return -1;
  }
  // according to the ietf draft this could be all zeroes
  uint8_t salt[32]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0,sizeof rw0);
    sodium_munlock(rw,sizeof rw);
    return -1;
  }
  sodium_munlock(rw0,sizeof rw0);
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

#ifdef TRACE
  dump((uint8_t*) rw, 32, "key ");
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "k_s\nplain user rec ");
#endif
  // p_s ←_R Z_q
  randombytes(rec->p_s, crypto_scalarmult_SCALARBYTES); // random server secret key

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "p_s\nplain user rec ");
#endif
  // p_u ←_R Z_q
  randombytes(rec->c.p_u, crypto_scalarmult_SCALARBYTES); // random user secret key

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "p_u\nplain user rec ");
#endif
  // P_s := g^p_s
  crypto_scalarmult_base(rec->P_s, rec->p_s);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "P_s\nplain user rec ");
#endif
  // P_u := g^p_u
  crypto_scalarmult_base(rec->P_u, rec->c.p_u);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "P_u\nplain user rec ");
#endif
  // copy Pubkeys also into rec.c
  memcpy(rec->c.P_u, rec->P_u,crypto_scalarmult_BYTES*2);

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN, "P_[us] -> c\nplain user rec ");
  printf("OPAQUE_ENVELOPE_META_LEN: %ld\n", OPAQUE_ENVELOPE_META_LEN);
  printf("OPAQUE_BLOB_LEN: %ld\n", OPAQUE_BLOB_LEN);
  printf("sizeof(Opaque_Blob): %ld\n", sizeof(Opaque_Blob) );
  printf("OPAQUE_USER_RECORD_LEN: %ld\n", OPAQUE_USER_RECORD_LEN);
  printf("sizeof(Opaque_UserRecord): %ld\n", sizeof(Opaque_UserRecord));
#endif

  // c ← AuthEnc_rw(p_u,P_u,P_s);
  const uint16_t SecEnv_len = crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES*2;
  if(0!=opaque_envelope(rw,
                        // SecEnv, SecEnv_len
                        ((uint8_t*)&rec->c)+crypto_hash_sha256_BYTES+sizeof(uint16_t), SecEnv_len,
                        // ClrEnv, ClrEnv_len
                        ClrEnv, ClrEnv_len,
                        // envelope
                        ((uint8_t*)&rec->c),
                        export_key)) {
    return -1;
  }
  rec->env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "plain user rec ");
#endif


  sodium_munlock(rw, sizeof(rw));

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN+ClrEnv_len, "cipher user rec ");
#endif
  return 0;
}

//(UsrSession, sid , ssid , S, pw): U picks r, x_u ←_R Z_q ; sets α := (H^0(pw))^r and
//X_u := g^x_u ; sends α and X_u to S.
// more or less corresponds to CreateCredentialRequest in the ietf draft
int opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t _pub[OPAQUE_USER_SESSION_PUBLIC_LEN]) {
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret*) _sec;
  Opaque_UserSession *pub = (Opaque_UserSession*) _pub;

  if(0!=sphinx_blindPW(pw, pwlen, sec->r, pub->alpha)) return -1;
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
  memcpy(sec->alpha, pub->alpha, crypto_core_ristretto255_BYTES);

  // x_u ←_R Z_q
  randombytes(sec->x_u, crypto_scalarmult_SCALARBYTES);

  // nonceU
  randombytes(sec->nonceU, OPAQUE_NONCE_BYTES);
  memcpy(pub->nonceU, sec->nonceU, OPAQUE_NONCE_BYTES);

  // X_u := g^x_u
  crypto_scalarmult_base(pub->X_u, sec->x_u);
#ifdef TRACE
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "sec ");
  dump(_pub,OPAQUE_USER_SESSION_PUBLIC_LEN, "pub ");
#endif
  return 0;
}

// more or less corresponds to CreateCredentialResponse in the ietf draft
// 2. (SvrSession, sid , ssid ): On input α from U, S proceeds as follows:
// (a) Checks that α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
// (c) Picks x_s ←_R Z_q and computes β := α^k_s and X_s := g^x_s ;
// (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f K (0);
// (e) Sends β, X s and c to U;
// (f) Outputs (sid , ssid , SK).
int opaque_session_srv(const uint8_t _pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t _rec[OPAQUE_USER_RECORD_LEN], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t _resp[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[crypto_secretbox_KEYBYTES],  Opaque_ServerAuthCTX *ctx) {

  Opaque_UserSession *pub = (Opaque_UserSession *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;

#ifdef TRACE
  dump(_pub, sizeof(Opaque_UserSession), "session srv pub ");
  dump(_rec, OPAQUE_USER_SESSION_PUBLIC_LEN, "session srv rec ");
#endif

  // (a) Checks that α ∈ G^∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(pub->alpha)!=1) return -1;

  // (b) Retrieves file[sid] = {k_s, p_s, P_s, P_u, c};
  // provided as parameter rec

  // (c) Picks x_s ←_R Z_q
  uint8_t x_s[crypto_scalarmult_SCALARBYTES];
  if(-1==sodium_mlock(x_s,sizeof x_s)) return -1;
  randombytes(x_s, crypto_scalarmult_SCALARBYTES);
#ifdef TRACE
  dump(x_s, sizeof(x_s), "session srv x_s ");
#endif

#ifdef TRACE
  dump(rec->k_s, sizeof(rec->k_s), "session srv k_s ");
  dump(pub->alpha, sizeof(pub->alpha), "session srv alpha ");
#endif

  // computes β := α^k_s
  if (crypto_scalarmult_ristretto255(resp->beta, rec->k_s, pub->alpha) != 0) {
    sodium_munlock(x_s, sizeof x_s);
    return -1;
  }

  // X_s := g^x_s;
  crypto_scalarmult_base(resp->X_s, x_s);
#ifdef TRACE
  dump(resp->X_s, sizeof(resp->X_s), "session srv X_s ");
#endif

  // nonceS
  randombytes(resp->nonceS, OPAQUE_NONCE_BYTES);

  // mixing in things from the ietf cfrg spec
  char info[crypto_hash_sha256_BYTES];
  calc_info(info, pub->nonceU, resp->nonceS, ids);
  Opaque_Keys keys;
  sodium_mlock(&keys,sizeof(keys));

  // (d) Computes K := KE(p_s, x_s, P_u, X_u) and SK := f_K(0);
  // paper instantiates HMQV, we do only triple-dh
#ifdef TRACE
  dump(rec->p_s,crypto_scalarmult_SCALARBYTES, "rec->p_s ");
  dump(x_s,crypto_scalarmult_SCALARBYTES, "x_s ");
  dump(rec->P_u,crypto_scalarmult_BYTES, "rec->P_u ");
  dump(pub->X_u,crypto_scalarmult_BYTES, "pub->X_u ");
#endif
  if(0!=opaque_server_3dh(&keys, rec->p_s, x_s, rec->P_u, pub->X_u, info)) {
    sodium_munlock(x_s, sizeof(x_s));
    sodium_munlock(&keys,sizeof(keys));
    return -1;
  }
  sodium_munlock(x_s, sizeof(x_s));
#ifdef TRACE
  dump(keys.sk, sizeof(keys.sk), "session srv sk ");
  dump(keys.km3,crypto_auth_hmacsha256_KEYBYTES,"session srv km3 ");
#endif

  // (e) Sends β, X_s and c to U;
  memcpy(&resp->c, &rec->c, rec->env_len);
  memcpy(&resp->env_len, &rec->env_len, sizeof rec->env_len);

  // Mac(Km2; xcript2) - from the ietf cfrg draft
  uint8_t xcript[crypto_hash_sha256_BYTES];
  get_xcript_srv(xcript, pub, resp, ctx, infos);
  crypto_auth_hmacsha256(resp->auth,                          // out
                         xcript,                              // in
                         crypto_hash_sha256_BYTES,            // len(in)
                         keys.km2);                           // key
#ifdef TRACE
  dump(resp->auth, sizeof resp->auth, "resp->auth ");
  dump(keys.km2, sizeof keys.km2, "km2 ");
#endif

  memcpy(sk,keys.sk,sizeof(keys.sk));
  memcpy(ctx->km3,keys.km3,sizeof(keys.km3));
  sodium_munlock(&keys,sizeof(keys));

#ifdef TRACE
  dump(resp->auth, sizeof(resp->auth), "session srv auth ");
#endif

  // (f) Outputs (sid , ssid , SK).
  // e&f handled as parameters

#ifdef TRACE
  dump(_resp,OPAQUE_SERVER_SESSION_LEN, "session srv resp ");
#endif

  return 0;
}

// more or less corresponds to RecoverCredentials in the ietf draft
// 3. On β, X_s and c from S, U proceeds as follows:
// (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
// (b) Computes rw := H(key, pw|β^1/r );
// (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
//     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
// (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
// (e) Outputs (sid, ssid, SK).
int opaque_session_usr_finish(const uint8_t *pw, const size_t pwlen,
                              const uint8_t _resp[OPAQUE_SERVER_SESSION_LEN],
                              const uint8_t _sec[OPAQUE_USER_SESSION_SECRET_LEN],
                              const uint8_t *key, const uint64_t key_len,
                              const Opaque_Ids *ids,
                              Opaque_App_Infos *infos,
                              uint8_t *sk,
                              uint8_t rwd[crypto_secretbox_KEYBYTES],
                              uint8_t auth[crypto_auth_hmacsha256_BYTES],
                              uint8_t export_key[crypto_hash_sha256_BYTES]) {
  Opaque_ServerSession *resp = (Opaque_ServerSession *) _resp;
  Opaque_UserSession_Secret *sec = (Opaque_UserSession_Secret *) _sec;
#ifdef TRACE
  dump(pw,pwlen, "session user finish pw ");
  dump(key,key_len, "session user finish key ");
  dump(_sec,OPAQUE_USER_SESSION_SECRET_LEN, "session user finish sec ");
  dump(_resp,OPAQUE_SERVER_SESSION_LEN, "session user finish resp ");
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(resp->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir,sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, sec->r) != 0) {
    sodium_munlock(ir,sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump(sec->r,sizeof(sec->r), "session user finish r ");
  dump(ir,sizeof(ir), "session user finish r^-1 ");
#endif

  // h0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  uint8_t h0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(h0,sizeof h0)) {
    sodium_munlock(ir,sizeof ir);
    return -1;
  }
#ifdef TRACE
  dump(resp->beta,sizeof(resp->beta), "session user finish beta ");
#endif
  if (crypto_scalarmult_ristretto255(h0, ir, resp->beta) != 0) {
    sodium_munlock(ir,sizeof ir);
    sodium_munlock(h0,sizeof h0);
    return -1;
  }
  sodium_munlock(ir,sizeof ir);
#ifdef TRACE
  dump(h0,sizeof(h0), "session user finish h0 ");
#endif

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  if(-1==sodium_mlock(&state,sizeof state)) {
    sodium_munlock(h0,sizeof h0);
    return -1;
  }
  if(key != NULL) {
     crypto_generichash_init(&state, key, key_len, 32);
  } else {
    uint8_t domain[]="RFCXXXX"; // todo set after RFC is published
    crypto_generichash_init(&state, domain, (sizeof domain) - 1, 32);
  }
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  sodium_munlock(h0, sizeof(h0));

  uint8_t rw0[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rw0,sizeof rw0)) {
    sodium_munlock(&state, sizeof(state));
    return -1;
  }
  crypto_generichash_final(&state, rw0, sizeof(rw0));
  sodium_munlock(&state, sizeof(state));

#ifdef TRACE
  dump(rw0,sizeof(rw0), "session user finish rw0 ");
#endif

  uint8_t rw[crypto_secretbox_KEYBYTES];
  if(-1==sodium_mlock(rw,sizeof rw)) {
    sodium_munlock(rw0, sizeof(rw0));
    return -1;
  }
  uint8_t salt[32]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0, sizeof rw0);
    sodium_munlock(rw, sizeof rw);
    return -1;
  }
  sodium_munlock(rw0, sizeof rw0);
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

#ifdef TRACE
  dump(rw,sizeof(rw), "session user finish rw ");
#endif

  // (c) Computes AuthDec_rw(c). If the result is ⊥, outputs (abort, sid , ssid ) and halts.
  //     Otherwise sets (p_u, P_u, P_s ) := AuthDec_rw (c);
  if(resp->env_len > OPAQUE_ENVELOPE_META_LEN + ((1<<17) - 2)  ) {
    sodium_munlock(rw, sizeof rw);
    return -1; // avoid integer overflow in next line
  }
  uint8_t *ClrEnv, env[resp->env_len];
  uint16_t ClrEnv_len, SecEnv_len;
  memcpy(env, &resp->c, resp->env_len);
  if(0!=opaque_envelope_open(rw, ((uint8_t*)&resp->c), resp->env_len, ((uint8_t*)&resp->c)+crypto_hash_sha256_BYTES+sizeof(uint16_t), &SecEnv_len, &ClrEnv, &ClrEnv_len, export_key)) {
    sodium_munlock(rw, sizeof(rw));
    return -1;
  }
#ifdef TRACE
  dump((uint8_t*)&resp->c, resp->env_len, "unlocked blob ");
#endif

  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*) "rwd", 3);
  sodium_munlock(rw, sizeof(rw));

  Opaque_Blob *c = (Opaque_Blob *) &resp->c;

  // mixing in things from the ietf cfrg spec
  char info[crypto_hash_sha256_BYTES];
  calc_info(info, sec->nonceU, resp->nonceS, ids);
  Opaque_Keys keys;
  sodium_mlock(&keys,sizeof(keys));

  // (d) Computes K := KE(p_u, x_u, P_s, X_s) and SK := f_K(0);
#ifdef TRACE
  dump(c->p_u,crypto_scalarmult_SCALARBYTES, "c->p_u ");
  dump(sec->x_u,crypto_scalarmult_SCALARBYTES, "sec->x_u ");
  dump(c->P_s,crypto_scalarmult_BYTES, "c->P_s ");
  dump(resp->X_s,crypto_scalarmult_BYTES, "sec->X_s ");
#endif
  if(0!=opaque_user_3dh(&keys, c->p_u, sec->x_u, c->P_s, resp->X_s, info)) {
    sodium_munlock(&keys, sizeof(keys));
    return -1;
  }

  uint8_t xcript[crypto_hash_sha256_BYTES];
  uint8_t X_u[crypto_scalarmult_BYTES];
  crypto_scalarmult_base(X_u, sec->x_u);
  get_xcript_usr(xcript, sec, resp, env, X_u, infos, 0);
#ifdef TRACE
  dump(resp->auth, sizeof resp->auth, "resp->auth ");
  dump(keys.km2, sizeof keys.km2, "km2 ");
#endif
  if(0!=crypto_auth_hmacsha256_verify(resp->auth, xcript, crypto_hash_sha256_BYTES, keys.km2)) {
    sodium_munlock(&keys, sizeof(keys));
    if(rwd!=NULL) sodium_memzero(rwd, crypto_secretbox_KEYBYTES);
    return -1;
  }

  memcpy(sk,keys.sk,sizeof(keys.sk));
#ifdef TRACE
  dump(keys.km3,crypto_auth_hmacsha256_KEYBYTES,"session user finish km3 ");
#endif

  if(auth) {
    get_xcript_usr(xcript, sec, resp, env, X_u, infos, 1);
    crypto_auth_hmacsha256(auth, xcript, crypto_hash_sha256_BYTES, keys.km3);
#ifdef TRACE
  dump(xcript, crypto_hash_sha256_BYTES, "session user finish xcript ");
  if(infos)
    dump((uint8_t*) infos, sizeof(Opaque_App_Infos), "session user finish infos ");
  dump(auth,crypto_auth_hmacsha256_BYTES, "session user finish auth ");
#endif
  }

  sodium_munlock(&keys, sizeof(keys));

  // (e) Outputs (sid, ssid, SK).

  return 0;
}

// extra function to implement the hmac based auth as defined in the ietf cfrg draft
int opaque_session_server_auth(Opaque_ServerAuthCTX *ctx, const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos) {
  if(infos!=NULL) {
    if(infos->info3!=NULL) crypto_hash_sha256_update(&ctx->xcript_state, infos->info3, infos->info3_len);
    if(infos->einfo3!=NULL) crypto_hash_sha256_update(&ctx->xcript_state, infos->einfo3, infos->einfo3_len);
  }
  uint8_t xcript[crypto_hash_sha256_BYTES];
  crypto_hash_sha256_final(&ctx->xcript_state, xcript);
#ifdef TRACE
  dump(ctx->km3,crypto_auth_hmacsha256_KEYBYTES,"km3 ");
  dump(xcript, crypto_hash_sha256_BYTES, "xcript ");
  if(infos)
    dump((uint8_t*)infos, sizeof(Opaque_App_Infos), "infos ");
  dump(authU,crypto_auth_hmacsha256_BYTES, "authU ");
#endif
  return crypto_auth_hmacsha256_verify(authU, xcript, crypto_hash_sha256_BYTES, ctx->km3);
}

// variant where the secrets of U never touch S unencrypted

// U computes: blinded PW
// called CreateRegistrationRequest in the ietf cfrg rfc draft
int opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  return sphinx_blindPW(pw, pwlen, r, alpha);
}

// initUser: S
// (1) checks α ∈ G^∗ If not, outputs (abort, sid , ssid ) and halts;
// (2) generates k_s ←_R Z_q,
// (3) computes: β := α^k_s,
// (4) finally generates: p_s ←_R Z_q, P_s := g^p_s;
// called CreateRegistrationResponse in the ietf cfrg rfc draft
int opaque_private_init_srv_respond(const uint8_t *alpha, uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]) {
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
// (b) Computes rw := H(key, pw | β^1/r );
// (c) p_u ←_R Z_q
// (d) P_u := g^p_u,
// (e) c ← AuthEnc_rw (p_u, P_u, P_s);
// called FinalizeRequest in the ietf cfrg rfc draft
int opaque_private_init_usr_respond(const uint8_t *pw, const size_t pwlen,
                                    const uint8_t *r,
                                    const uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN],
                                    const uint8_t *key, const uint64_t key_len,        // contributes to the final rwd calculation as a key to the hash
                                    const uint8_t *ClrEnv, const uint16_t ClrEnv_len,
                                    uint8_t _rec[OPAQUE_USER_RECORD_LEN],
                                    uint8_t rwd[crypto_secretbox_KEYBYTES],
                                    uint8_t export_key[crypto_hash_sha256_BYTES]) {

  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;
#ifdef TRACE
  memset(_rec,0,OPAQUE_USER_RECORD_LEN);
#endif

  // (a) Checks that β ∈ G ∗ . If not, outputs (abort, sid , ssid ) and halts;
  if(crypto_core_ristretto255_is_valid_point(pub->beta)!=1) return -1;

  // (b) Computes rw := H(pw, β^1/r );
  // invert r = 1/r
  uint8_t ir[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ir, sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, r) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }

  // H0 = β^(1/r)
  // beta^(1/r) = h(pwd)^k
  uint8_t h0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(h0,sizeof h0)) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }
  if (crypto_scalarmult_ristretto255(h0, ir, pub->beta) != 0) {
    sodium_munlock(ir, sizeof ir);
    sodium_munlock(h0, sizeof h0);
    return -1;
  }
  sodium_munlock(ir, sizeof ir);

  // rw = H(pw, β^(1/r))
  crypto_generichash_state state;
  if(-1==sodium_mlock(&state, sizeof state)) {
    sodium_munlock(h0, sizeof h0);
    return -1;
  }
  if(key != NULL) {
     crypto_generichash_init(&state, key, key_len, 32);
  } else {
     crypto_generichash_init(&state, 0, 0, 32);
  }
  crypto_generichash_update(&state, pw, pwlen);
  crypto_generichash_update(&state, h0, 32);
  sodium_munlock(h0, sizeof(h0));

  uint8_t rw0[32];
  if(-1==sodium_mlock(rw0, sizeof rw0)) {
    sodium_munlock(&state, sizeof state);
    return -1;
  }
  crypto_generichash_final(&state, rw0, sizeof rw0);
  sodium_munlock(&state, sizeof(state));

#ifdef TRACE
  dump((uint8_t*) rw0, 32, "rw0 ");
#endif

  uint8_t rw[32];
  if(-1==sodium_mlock(rw, sizeof rw)) {
    sodium_munlock(rw0, sizeof rw0);
    return -1;
  }
  // salt - according to the ietf draft this could be all zeroes
  uint8_t salt[32]={0};
  if (crypto_pwhash(rw, sizeof rw, (const char*) rw0, sizeof rw0, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    sodium_munlock(rw0, sizeof(rw0));
    sodium_munlock(rw, sizeof(rw));
    return -1;
  }
  sodium_munlock(rw0, sizeof(rw0));
  crypto_kdf_hkdf_sha256_extract(rw, (uint8_t*) "RwdU", 4, rw, sizeof rw);

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

  // c ← AuthEnc_rw(p_u,P_u,P_s);
#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN, "plain user rec ");
#endif

  const uint16_t SecEnv_len = crypto_scalarmult_SCALARBYTES+crypto_scalarmult_BYTES*2;
  if(0!=opaque_envelope(rw,
                        // SecEnv, SecEnv_len
                        ((uint8_t*)&rec->c)+crypto_hash_sha256_BYTES+sizeof(uint16_t), SecEnv_len,
                        ClrEnv, ClrEnv_len,
                        // envelope
                        ((uint8_t*)&rec->c),
                        export_key)) {
    return -1;
  }
  rec->env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;

#ifdef TRACE
  dump(_rec, OPAQUE_USER_RECORD_LEN, "cipher user rec ");
#endif

  if(rwd!=NULL)
    crypto_generichash(rwd, crypto_secretbox_KEYBYTES, rw, crypto_secretbox_KEYBYTES, (const uint8_t*)"rwd", 3);
  sodium_munlock(rw, sizeof(rw));

  return 0;
}

// S records file[sid ] := {k_s, p_s, P_s, P_u, c}.
// called StoreUserRecord in the ietf cfrg rfc draft
void opaque_private_init_srv_finish(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN], uint8_t _rec[OPAQUE_USER_RECORD_LEN]) {
  Opaque_RegisterSec *sec = (Opaque_RegisterSec *) _sec;
  Opaque_RegisterPub *pub = (Opaque_RegisterPub *) _pub;
  Opaque_UserRecord *rec = (Opaque_UserRecord *) _rec;

  memcpy(rec->k_s, sec->k_s, sizeof rec->k_s);
  memcpy(rec->p_s, sec->p_s, sizeof rec->p_s);
  memcpy(rec->P_s, pub->P_s, sizeof rec->P_s);
#ifdef TRACE
  dump((uint8_t*) rec, OPAQUE_USER_RECORD_LEN, "user rec ");
#endif
}
