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

    This file implements the PKI-free PAKE protocol
    as specified on page 18 of: https://eprint.iacr.org/2015/1099
*/

#include <stdint.h>
#include <string.h>
#include "decaf.h"
#include <crypto_generichash.h>
#include <randombytes.h>
#include <sodium/utils.h>

// server shares pk as P_s with client_init
void pake_server_init(uint8_t *p_s, uint8_t *P_s) {
  randombytes(p_s, DECAF_X25519_PRIVATE_BYTES); // random secret key
  decaf_x25519_derive_public_key(P_s, p_s);
}

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

// sends c, C, k_s , P_u , m_u to server
void pake_client_init(const uint8_t *rwd, const size_t rwd_len, const uint8_t *P_s,  // input params
                        uint8_t k_s[32], uint8_t c[32], uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]) { // output params
  uint8_t z[32], tmp[32];
  // U chooses z ∈_R {0, 1}^τ
  randombytes(z, 32);
  // k_s ∈_R Z_q
  randombytes(k_s, 32);

  // c = z ⊕ F_k_s(rwd)
  oprf(rwd, rwd_len, k_s, c);
  int i, *ci=(int*) c, *zi=(int*) z;
  for(i=0;i<8;i++) ci[i]^=zi[i];

  // r = f_z(0)
  uint8_t r[32];
  memset(tmp,0,32);
  crypto_generichash(r, 32, tmp, 32, z, 32);

  // C = H(r, rwd, c)
  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, r, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, c, 32);
  crypto_generichash_final(&state, C, 32);
  decaf_bzero(r, sizeof(r));

  // p_u = f_z(1) mod q
  uint8_t p_u[DECAF_X25519_PRIVATE_BYTES];
  memset(tmp,1,32);
  crypto_generichash(p_u, DECAF_X25519_PRIVATE_BYTES, tmp, 32, z, 32);

  // computes P_u = g^p_u
  decaf_x25519_derive_public_key(P_u, p_u);
  decaf_bzero(p_u, sizeof(p_u));

  // m_u = f_z (2, P_u, P_s)
  memset(tmp,2,32);
  crypto_generichash_init(&state, z, 32, 32);
  crypto_generichash_update(&state, tmp, 32);
  crypto_generichash_update(&state, P_u, 32);
  crypto_generichash_update(&state, P_s, 32);
  crypto_generichash_final(&state, m_u, 32);
  decaf_bzero(&state, sizeof(state));
  decaf_bzero(z, sizeof(z));
}

// done by user
void pake_start_pake(const uint8_t *rwd, const size_t rwd_len, // input params
                       uint8_t alpha[32], uint8_t x_u[32],      // output params
                       uint8_t X_u[32], uint8_t sp[32]) {
  // choose ρ, x_u ← Z_q
  randombytes(sp, 32);
  decaf_255_scalar_t p;
  decaf_255_scalar_decode_long(p, sp, 32);

  randombytes(x_u, DECAF_X25519_PRIVATE_BYTES);

  // α = (H0(rwd))^ρ
  uint8_t h0[32];
  crypto_generichash(h0, sizeof h0, rwd, rwd_len, 0, 0);
  decaf_255_point_t H0;
  decaf_255_point_from_hash_nonuniform(H0, h0);
  decaf_bzero(h0, sizeof(h0));
  decaf_255_point_scalarmul(H0, H0, p);
  decaf_255_scalar_destroy(p);
  decaf_255_point_encode(alpha, H0);
  decaf_255_point_destroy(H0);

  // X_u = g^x_u
  decaf_x25519_derive_public_key(X_u, x_u);
}

static void derive_secret(uint8_t *mk, const uint8_t *sec) {
  // workaround hash sec from 96 bytes down to 64,
  // as blake can only handle 64 as a key
  uint8_t hashkey[64];
  crypto_generichash(hashkey, sizeof hashkey, sec, 96, 0, 0);

  // and hash for the result SK = f_K(0)
  uint8_t zero[32];
  memset(zero,0,32);
  crypto_generichash(mk, DECAF_X25519_PUBLIC_BYTES,  // output
                     zero, 32,                       // msg
                     hashkey, sizeof(hashkey));      // key

  decaf_bzero(hashkey, sizeof(hashkey));
}

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

// sends to U β (from this),
//            c, C, P_u , m_u, (received from U in init)
//            P_s (from server init),
//            X_s (from here)
int pake_server_pake(const uint8_t alpha[32], const uint8_t X_u[32],  // input params
                       const uint8_t k_s[32], const uint8_t P_u[32],
                       const uint8_t p_s[32],
                       uint8_t beta[32], uint8_t X_s[32],               // output params
                       uint8_t SK[DECAF_X25519_PUBLIC_BYTES]) {         // this is the final result: shared secret from the PAKE
  decaf_255_point_t Alpha;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Alpha, alpha, DECAF_FALSE)) return 1;

  // Picks x_s ∈_R Z_q
  uint8_t x_s[DECAF_X25519_PRIVATE_BYTES];
  randombytes(x_s, DECAF_X25519_PRIVATE_BYTES); // random secret key

  // computes β = α^k_s
  decaf_255_point_t Beta;
  decaf_255_scalar_t K_s;
  decaf_255_scalar_decode_long(K_s, k_s, 32);
  decaf_255_point_scalarmul(Beta, Alpha, K_s);
  decaf_255_point_destroy(Alpha);
  decaf_255_scalar_destroy(K_s);
  decaf_255_point_encode(beta, Beta);
  decaf_255_point_destroy(Beta);

  // X_s = g^x_s
  decaf_x25519_derive_public_key(X_s, x_s);

  // Computes K = KE(p_s , x_s , P_u , X_u)
  // and outputs session key SK = f_K(0)
  server_kex(SK, p_s, x_s, P_u, X_u);
  decaf_bzero(x_s, sizeof(x_s));

  return 0;
}

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

int pake_user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t sp[32],
                     const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32],
                     const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32],
                     const uint8_t P_s[32], const uint8_t X_s[32],
                     uint8_t SK[DECAF_X25519_PUBLIC_BYTES]) {
  // note: β, c, C, P_u , m_u , P_s , X_s are sent by server_pake
  // sp(==p) is from start_pake
  // Sets z = c ⊕ H(rwd, β^(1/ρ)), r = f_z(0), p_u = f_z (1) mod q.

  // calculate z
  // z = c ⊕ H(rwd, β^(1/ρ))
  decaf_255_scalar_t p;
  decaf_255_scalar_decode_long(p, sp, 32);
  // p = 1/p
  if(decaf_255_scalar_invert(p, p)!=DECAF_SUCCESS) return 1;

  // H0 = β^(1/ρ)
  decaf_255_point_t H0, Beta;
  if(DECAF_SUCCESS!=decaf_255_point_decode(Beta, beta, DECAF_FALSE)) return 1;
  decaf_255_point_scalarmul(H0, Beta, p);
  decaf_255_scalar_destroy(p);
  decaf_255_point_destroy(Beta);
  uint8_t h0[32], h[32];
  decaf_255_point_encode(h0, H0);
  decaf_255_point_destroy(H0);

  // h = H(rwd, β^(1/ρ))
  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, h, 32);
  decaf_bzero(h0, sizeof(h0));

  // z = c ⊕ H(rwd, β^(1/ρ))
  uint8_t z[32];
  int i, *ci=(int*) c, *zi=(int*) z, *hi=(int*) h;
  for(i=0;i<8;i++) zi[i]=ci[i]^hi[i];
  // end of calculate z

  // r = f_z(0)
  uint8_t r[32], tmp[32];
  memset(tmp,0,32);
  crypto_generichash(r, 32, tmp, 32, z, 32);

  // p_u = f_z (1) mod q.
  uint8_t p_u[32];
  memset(tmp,1,32);
  crypto_generichash(p_u, 32, tmp, 32, z, 32);

  // abort if  C != H(r, rwd, c) && m_u != f_z(2,P_u,P_s)

  // calculate C != H(r, rwd, c)
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, r, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, c, 32);
  crypto_generichash_final(&state, h, 32);
  decaf_bzero(r, sizeof(r));
  if(sodium_memcmp(h,C,32)!=0) {
    decaf_bzero(h, sizeof(h));
    decaf_bzero(&state, sizeof(state));
    decaf_bzero(z, sizeof(z));
    decaf_bzero(p_u, sizeof(p_u));
    return 1;
  }

  // calculate f_z(2,P_u,P_s)
  memset(tmp,2,32);
  crypto_generichash_init(&state, z, 32, 32);
  crypto_generichash_update(&state, tmp, 32);
  crypto_generichash_update(&state, P_u, 32);
  crypto_generichash_update(&state, P_s, 32);
  crypto_generichash_final(&state, h, 32);
  // abort if m_u != f_z(2,P_u,P_s)
  decaf_bzero(&state, sizeof(state));
  decaf_bzero(z, sizeof(z));
  if(sodium_memcmp(h,m_u,32)!=0) {
    decaf_bzero(h, sizeof(h));
    decaf_bzero(p_u, sizeof(p_u));
    return 1;
  }
  decaf_bzero(h, sizeof(h));

  // calculate shared secret of PAKE
  user_kex(SK, p_u, x_u, P_s, X_s);
  decaf_bzero(p_u, sizeof(p_u));

  return 0;
}
