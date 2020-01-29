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

    This file implements the PKI-free PAKE protocol
    as specified on page 18 of: https://eprint.iacr.org/2015/1099
*/

#include "common.h"

// server shares pk as P_s with client_init
void pake_server_init(uint8_t *p_s, uint8_t *P_s) {
  randombytes(p_s, crypto_scalarmult_SCALARBYTES); // random secret key
  crypto_scalarmult_base(P_s, p_s);
#ifdef TRACE
  dump(p_s, 32, "p_s");
  dump(P_s, 32, "P_s");
#endif
}

// sends c, C, k_s , P_u , m_u to server
int pake_client_init(const uint8_t *rwd, const size_t rwd_len, const uint8_t *P_s,  // input params
                        uint8_t k_s[32], uint8_t c[32], uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]) { // output params
  uint8_t z[32], tmp[32];
  if(-1==sodium_mlock(z,sizeof z)) return -1;
  // U chooses z ∈_R {0, 1}^τ
  crypto_core_ristretto255_scalar_random(z);
  // k_s ∈_R Z_q
  crypto_core_ristretto255_scalar_random(k_s);
#ifdef TRACE
  dump(z, 32, "z");
  dump(k_s, 32, "k_s");
#endif

  // c = z ⊕ F_k_s(rwd)
  if(0!=sphinx_oprf(rwd, rwd_len, k_s, 0, 0, c)) {
    sodium_munlock(z, sizeof(z));
    return -1;
  }
#ifdef TRACE
  dump(c, 32, "c");
#endif
  int i, *ci=(int*) c, *zi=(int*) z;
  for(i=0;i<8;i++) ci[i]^=zi[i];
#ifdef TRACE
  dump(c, 32, "ci");
#endif

  // r = f_z(0)
  uint8_t r[32];
  if(-1==sodium_mlock(r,sizeof r)) {
    sodium_munlock(z, sizeof(z));
    return -1;
  }
  memset(tmp,0,32);
  crypto_generichash(r, 32, tmp, 32, z, 32);
#ifdef TRACE
  dump(r, 32, "r");
#endif

  // C = H(r, rwd, c)
  crypto_generichash_state state;
  if(-1==sodium_mlock(&state,sizeof state)) {
    sodium_munlock(z, sizeof(z));
    sodium_munlock(r, sizeof(r));
    return -1;
  }
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, r, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, c, 32);
  crypto_generichash_final(&state, C, 32);
  sodium_munlock(r, sizeof(r));
#ifdef TRACE
  dump(C, 32, "C");
#endif

  // p_u = f_z(1) mod q
  uint8_t p_u[crypto_scalarmult_SCALARBYTES];
  if(-1==sodium_mlock(p_u, sizeof(p_u))) {
    sodium_munlock(z, sizeof(z));
    sodium_munlock(&state,sizeof state);
    return -1;
  }
  memset(tmp,1,32);
  crypto_generichash(p_u, crypto_scalarmult_SCALARBYTES, tmp, 32, z, 32);
#ifdef TRACE
  dump(p_u, 32, "p_u");
#endif

  // computes P_u = g^p_u
  crypto_scalarmult_base(P_u, p_u);
#ifdef TRACE
  dump(P_u, 32, "P_u");
#endif
  sodium_munlock(p_u, sizeof(p_u));

  // m_u = f_z (2, P_u, P_s)
  memset(tmp,2,32);
  crypto_generichash_init(&state, z, 32, 32);
  crypto_generichash_update(&state, tmp, 32);
  crypto_generichash_update(&state, P_u, 32);
  crypto_generichash_update(&state, P_s, 32);
  crypto_generichash_final(&state, m_u, 32);
  sodium_munlock(&state, sizeof(state));
  sodium_munlock(z, sizeof(z));
#ifdef TRACE
  dump(m_u, 32, "m_u");
#endif
  return 0;
}

// done by user
int pake_start_pake(const uint8_t *rwd, const size_t rwd_len,   // input params
                       uint8_t alpha[32], uint8_t x_u[32],      // output params
                       uint8_t X_u[32], uint8_t p[32]) {


  // blind rwd with q
  if(0!=sphinx_blindPW(rwd, rwd_len, p, alpha)) {
    return -1;
  }
  // choose x_u ← Z_q
  randombytes(x_u, crypto_scalarmult_SCALARBYTES);
#ifdef TRACE
  dump(x_u, 32, "x_u");
#endif
  // X_u = g^x_u
  crypto_scalarmult_base(X_u, x_u);
#ifdef TRACE
  dump(X_u, 32, "X_u");
#endif
  return 0;
}

// sends to U β (from this),
//            c, C, P_u , m_u, (received from U in init)
//            P_s (from server init),
//            X_s (from here)
int pake_server_pake(const uint8_t alpha[32], const uint8_t X_u[32],    // input params
                       const uint8_t k_s[32], const uint8_t P_u[32],
                       const uint8_t p_s[32],
                       uint8_t beta[32], uint8_t X_s[32],               // output params
                       uint8_t SK[crypto_generichash_BYTES]) {          // this is the final result: shared secret from the PAKE
  if(0==crypto_core_ristretto255_is_valid_point(alpha)) return -1;

  // Picks x_s ∈_R Z_q
  uint8_t x_s[crypto_scalarmult_SCALARBYTES];
  if(-1==sodium_mlock(x_s, sizeof x_s)) return -1;
  randombytes(x_s, crypto_scalarmult_SCALARBYTES); // random secret key
#ifdef TRACE
  dump(x_s, 32, "x_s");
#endif

  // computes β = α^k_s
  if (crypto_scalarmult_ristretto255(beta, k_s, alpha) != 0) {
    sodium_munlock(x_s, sizeof(x_s));
    return -1;
  }
#ifdef TRACE
  dump(beta, 32, "beta");
#endif

  // X_s = g^x_s
  crypto_scalarmult_base(X_s, x_s);
#ifdef TRACE
  dump(X_s, 32, "X_s");
#endif

  // Computes K = KE(p_s , x_s , P_u , X_u)
  // and outputs session key SK = f_K(0)
  int ret = sphinx_server_3dh(SK, p_s, x_s, P_u, X_u);
  sodium_munlock(x_s, sizeof(x_s));

  return ret;
}

int pake_user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t p[32],
                     const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32],
                     const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32],
                     const uint8_t P_s[32], const uint8_t X_s[32],
                     uint8_t SK[crypto_generichash_BYTES]) {
  // note: β, c, C, P_u , m_u , P_s , X_s are sent by server_pake
  // p is from start_pake
  // Sets z = c ⊕ H(rwd, β^(1/ρ)), r = f_z(0), p_u = f_z (1) mod q.

  if(crypto_core_ristretto255_is_valid_point(beta)==0) {
    return -1;
  }

  // calculate z
  // z = c ⊕ H(rwd, β^(1/ρ))
  // p = 1/p
#ifdef TRACE
  dump(p, 32, "p");
#endif
  unsigned char ip[crypto_core_ristretto255_SCALARBYTES];
  if(-1==sodium_mlock(ip, sizeof(ip))) return -1;
  if (crypto_core_ristretto255_scalar_invert(ip, p) != 0) {
    sodium_munlock(ip, sizeof(ip));
    return -1;
  }
#ifdef TRACE
  dump(ip, 32, "ip");
#endif

  // H0 = β^(1/ρ)
  unsigned char h0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(h0, sizeof(h0))) {
    sodium_munlock(ip, sizeof(ip));
    return -1;
  }
  if (crypto_scalarmult_ristretto255(h0, ip, beta) != 0) {
    sodium_munlock(h0, sizeof(h0));
    sodium_munlock(ip, sizeof(ip));
    return -1;
  }
  sodium_munlock(ip, sizeof(ip));
#ifdef TRACE
  dump(h0, 32, "h0");
#endif
  uint8_t h[32];
  if(-1==sodium_mlock(h, sizeof h)) {
    sodium_munlock(h0, sizeof(h0));
    return -1;
  }

  // h = H(rwd, β^(1/ρ))
  crypto_generichash_state state;
  if(-1==sodium_mlock(&state, sizeof(state))) {
    sodium_munlock(h0, sizeof(h0));
    sodium_munlock(h, sizeof(h));
    return -1;
  }
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, h0, 32);
  crypto_generichash_final(&state, h, 32);
#ifdef TRACE
  dump(h, 32, "h");
#endif
  sodium_munlock(h0, sizeof(h0));

  // z = c ⊕ H(rwd, β^(1/ρ))
  uint8_t z[32];
  if(-1==sodium_mlock(z, sizeof(z))) {
    sodium_munlock(&state, sizeof(state));
    sodium_munlock(h, sizeof(h));
    return -1;
  }
  int i, *ci=(int*) c, *zi=(int*) z, *hi=(int*) h;
  for(i=0;i<8;i++) zi[i]=ci[i]^hi[i];
  // end of calculate z
#ifdef TRACE
  dump(z, 32, "z");
#endif

  // r = f_z(0)
  uint8_t r[32], tmp[32];
  if(-1==sodium_mlock(r,sizeof r)) {
    sodium_munlock(&state, sizeof(state));
    sodium_munlock(h, sizeof(h));
    sodium_munlock(z, sizeof(z));
    return -1;
  }
  memset(tmp,0,32);
  crypto_generichash(r, 32, tmp, 32, z, 32);
#ifdef TRACE
  dump(r, 32, "r");
#endif

  // p_u = f_z (1) mod q.
  uint8_t p_u[32];
  if(-1==sodium_mlock(p_u,sizeof p_u)) {
    sodium_munlock(&state, sizeof(state));
    sodium_munlock(h, sizeof(h));
    sodium_munlock(z, sizeof(z));
    sodium_munlock(r, sizeof(r));
    return -1;
  }
  memset(tmp,1,32);
  crypto_generichash(p_u, 32, tmp, 32, z, 32);
#ifdef TRACE
  dump(p_u, 32, "p_u");
#endif

  // abort if  C != H(r, rwd, c) && m_u != f_z(2,P_u,P_s)

  // calculate C != H(r, rwd, c)
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, r, 32);
  crypto_generichash_update(&state, rwd, rwd_len);
  crypto_generichash_update(&state, c, 32);
  crypto_generichash_final(&state, h, 32);
#ifdef TRACE
  dump(h, 32, "h");
#endif
  sodium_munlock(r, sizeof(r));

  if(sodium_memcmp(h,C,32)!=0) {
    sodium_munlock(h, sizeof(h));
    sodium_munlock(&state, sizeof(state));
    sodium_munlock(z, sizeof(z));
    sodium_munlock(p_u, sizeof(p_u));
    printf("C != H(r, rwd, c)\n");
    return -1;
  }

  // calculate f_z(2,P_u,P_s)
  memset(tmp,2,32);
  crypto_generichash_init(&state, z, 32, 32);
  crypto_generichash_update(&state, tmp, 32);
  crypto_generichash_update(&state, P_u, 32);
  crypto_generichash_update(&state, P_s, 32);
  crypto_generichash_final(&state, h, 32);
#ifdef TRACE
  dump(h, 32, "h");
#endif
  // abort if m_u != f_z(2,P_u,P_s)
  sodium_munlock(&state, sizeof(state));
  sodium_munlock(z, sizeof(z));
  if(sodium_memcmp(h,m_u,32)!=0) {
    sodium_munlock(h, sizeof(h));
    sodium_munlock(p_u, sizeof(p_u));
    return -1;
  }
  sodium_munlock(h, sizeof(h));

  // calculate shared secret of PAKE
  if(0!=sphinx_user_3dh(SK, p_u, x_u, P_s, X_s)) {
    sodium_munlock(p_u, sizeof(p_u));
    return -1;
  }
  sodium_munlock(p_u, sizeof(p_u));

  return 0;
}
