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
*/
#include <stdint.h>
#include <sodium.h>
#include "sphinx.h"

/* params:
 *
 * pwd, p_len: (input) the master password and its length
 * salt, salt_len: (input) salt for hashing the password, can both be NULL/0
 * bfac: (output) pointer to array of crypto_core_ristretto255_SCALARBYTES (32) bytes - the blinding factor
 * chal: (output) pointer to array of crypto_core_ristretto255_BYTES (32) bytes - the challenge
 * returns -1 on error, 0 on success
 */
int sphinx_challenge(const uint8_t *pwd, const size_t p_len, const uint8_t *salt, const size_t salt_len, uint8_t bfac[crypto_core_ristretto255_SCALARBYTES], uint8_t chal[crypto_core_ristretto255_BYTES]) {
  int ret = -1;
  // do the blinding
  uint8_t h0[crypto_core_ristretto255_HASHBYTES];
  if(-1==sodium_mlock(h0,sizeof h0)) return -1;
  // hash x with H0
  crypto_generichash(h0, crypto_core_ristretto255_HASHBYTES, pwd, p_len, salt, salt_len);
  unsigned char H0[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(H0,sizeof H0)) {
    sodium_munlock(h0,sizeof h0);
    return -1;
  }
  crypto_core_ristretto255_from_hash(H0, h0);
  sodium_munlock(h0,sizeof h0);

  // random blinding factor
  crypto_core_ristretto255_scalar_random(bfac);

  // chal = H0^r
  if (crypto_scalarmult_ristretto255(chal, bfac, H0) == 0) {
    ret = 0;
  }
  sodium_munlock(H0,sizeof H0);

  return ret;
}

/* params
 * chal: (input) the challenge, crypto_core_ristretto255_BYTES(32) bytes array
 * secret: (input) the secret contributing, crypto_core_ristretto255_SCALARBYTES (32) bytes array
 * resp: (output) the response, crypto_core_ristretto255_BYTES (32) bytes array
 * returns -1 on error, 0 on success
 */
int sphinx_respond(const uint8_t chal[crypto_core_ristretto255_BYTES], const uint8_t secret[crypto_core_ristretto255_SCALARBYTES], uint8_t resp[crypto_core_ristretto255_BYTES]) {
  // Checks that chal ∈ G^∗ . If not, abort;
  if(crypto_core_ristretto255_is_valid_point(chal)!=1) return -1;
  // server contributes k
  return crypto_scalarmult_ristretto255(resp, secret, chal);
}

/* params
 * pwd: (input) the password
 * p_len: (input) the password length
 * bfac: (input) bfac from challenge(), array of crypto_core_ristretto255_SCALARBYTES (32) bytes
 * resp: (input) the response from respond(), crypto_core_ristretto255_BYTES (32) bytes array
 * salt: (input) salt for the final password hashing, crypto_pwhash_SALTBYTES bytes array
 * rwd: (output) the derived password, crypto_core_ristretto255_BYTES (32) bytes array
 * returns -1 on error, 0 on success
 */
int sphinx_finish(const uint8_t *pwd, const size_t p_len, const uint8_t bfac[crypto_core_ristretto255_SCALARBYTES], const uint8_t resp[crypto_core_ristretto255_BYTES], const uint8_t salt[crypto_pwhash_SALTBYTES], uint8_t rwd[crypto_core_ristretto255_BYTES]) {
  // Checks that resp ∈ G^∗ . If not, abort;
  if(crypto_core_ristretto255_is_valid_point(resp)!=1) return -1;

  // invert bfac = 1/bfac
  unsigned char ir[crypto_core_ristretto255_SCALARBYTES];
  if(0!=sodium_mlock(ir,sizeof ir)) return -1;
  if (crypto_core_ristretto255_scalar_invert(ir, bfac) != 0) {
    sodium_munlock(ir, sizeof ir);
    return -1;
  }

  // resp^(1/bfac) = h(pwd)^secret == H0^k
  unsigned char H0_k[crypto_core_ristretto255_BYTES];
  if(-1==sodium_mlock(H0_k,sizeof H0_k)) return -1;
  if (crypto_scalarmult_ristretto255(H0_k, ir, resp) != 0) {
    sodium_munlock(ir, sizeof ir);
    sodium_munlock(H0_k,sizeof H0_k);
    return -1;
  }
  sodium_munlock(ir, sizeof ir);

  // hash(pwd||H0^k)
  crypto_generichash_state state;
  if(-1==sodium_mlock(&state,sizeof state)) {
    sodium_munlock(H0_k,sizeof H0_k);
    return -1;
  }
  crypto_generichash_init(&state, 0, 0, crypto_core_ristretto255_BYTES);
  crypto_generichash_update(&state, pwd, p_len);
  crypto_generichash_update(&state, H0_k, sizeof H0_k);
  crypto_generichash_final(&state, rwd, crypto_core_ristretto255_BYTES);
  sodium_munlock(H0_k,sizeof H0_k);
  sodium_munlock(&state,sizeof state);

  if (crypto_pwhash(rwd, crypto_core_ristretto255_BYTES, (const char*) rwd, crypto_core_ristretto255_BYTES, salt,
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
    /* out of memory */
    return -1;
  }

  return 0;
}
