/*
    @copyright 2018-2021, sphinx@ctrlc.hu
    This file is part of libsphinx.

    SPDX-FileCopyrightText: 2018-21, Stefan Marsiske
    SPDX-License-Identifier: LGPL-3.0-or-later

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
*/

#include "common.h"

#ifdef TRACE
void dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  fprintf(stderr,"%s ",msg);
  for(i=0;i<len;i++)
    fprintf(stderr,"%02x", p[i]);
  fprintf(stderr,"\n");
}
#endif // TRACE

#ifdef NORANDOM
void a_randombytes(void* const buf, const size_t len) {
  size_t i;
  for(i=0;i<len;i++) ((uint8_t*)buf)[i]=i&0xff;
}

void a_randomscalar(unsigned char* buf) {
  uint8_t tmp[64];
  a_randombytes(tmp, 64);
  crypto_core_ristretto255_scalar_reduce(buf, tmp);
}
#endif // NORANDOM

int sphinx_oprf(const uint8_t *pwd, const size_t pwd_len,
                const uint8_t k[crypto_core_ristretto255_SCALARBYTES],
                const uint8_t *key, const size_t key_len,
                uint8_t rwd[crypto_generichash_BYTES]) {
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
  if(key != NULL) {
     crypto_generichash_init(&state, key, key_len, 32);
  } else {
     crypto_generichash_init(&state, 0, 0, 32);
  }
  crypto_generichash_update(&state, pwd, pwd_len);
  crypto_generichash_update(&state, H0_k, sizeof H0_k);
  crypto_generichash_final(&state, rwd, 32);
#ifdef TRACE
  dump(rwd, 32, "rwd");
#endif
  sodium_munlock(H0_k,sizeof H0_k);
  sodium_munlock(&state, sizeof state);

  return 0;
}

int sphinx_blindPW(const uint8_t *pw, const size_t pwlen, uint8_t *r, uint8_t *alpha) {
  // sets α := (H^0(pw))^r
  // hash x with H^0
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  sodium_mlock(h0,sizeof h0);
  crypto_generichash(h0, sizeof h0, pw, pwlen, 0, 0);
#ifdef TRACE
  dump(h0, sizeof h0, "h0");
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
