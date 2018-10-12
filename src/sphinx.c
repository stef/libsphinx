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
#include <decaf.h>
#include <randombytes.h>
#include <crypto_generichash.h>
#include "sphinx.h"

/* params:
 *
 * pwd, p_len: (input) the master password and its length
 * bfac: (output) pointer to array of DECAF_255_SCALAR_BYTES (32) bytes - the blinding factor
 * chal: (output) pointer to array of DECAF_255_SER_BYTES (32) bytes - the challenge
 */
void sphinx_challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal) {
  unsigned char hash[DECAF_255_HASH_BYTES];
  crypto_generichash(hash, sizeof hash, pwd, p_len, 0, 0);
  // hashed_to_point with elligator the password hash
  decaf_255_point_t P;
  decaf_255_point_from_hash_nonuniform(P, hash);
  decaf_bzero(hash, sizeof(hash));

  // generate random blinding factor
  randombytes(bfac, DECAF_255_SCALAR_BYTES); // random blinding factor

  // convert the blinding factor into a scalar
  decaf_255_scalar_t b;
  decaf_255_scalar_decode_long(b, bfac, DECAF_255_SCALAR_BYTES);

  // blind the message: C=Pb
  decaf_255_point_t challenge;
  decaf_255_point_scalarmul(challenge, P, b);
  decaf_255_scalar_destroy(b);
  decaf_255_point_destroy(P);

  // serialize the challenge
  decaf_255_point_encode(chal, challenge);
  decaf_255_point_destroy(challenge);
}

/* params
 * chal: (input) the challenge, DECAF_255_SER_BYTES (32) bytes array
 * secret: (input) the secret contributing, DECAF_255_SCALAR_BYTES (32) bytes array
 * resp: (output) the response, DECAF_255_SER_BYTES (32) bytes array
 * returns 1 on error, 0 on success
 */
int sphinx_respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp) {
  // deserialize challenge into C
  decaf_255_point_t C, R;
  if(DECAF_SUCCESS!=decaf_255_point_decode(C, chal, DECAF_FALSE)) return 1;

  // peer contributes their own secret: R=Cy
  decaf_255_scalar_t key;
  decaf_255_scalar_decode_long(key, secret, DECAF_255_SCALAR_BYTES);
  decaf_255_point_scalarmul(R, C, key);
  decaf_255_scalar_destroy(key);
  decaf_255_point_destroy(C);

  decaf_255_point_encode(resp, R);
  decaf_255_point_destroy(R);

  return 0;
}

/* params
 * pwd: (input) the password
 * p_len: (input) the password length
 * bfac: (input) bfac from challenge(), array of DECAF_255_SCALAR_BYTES (32) bytes
 * resp: (input) the response from respond(), DECAF_255_SER_BYTES (32) bytes array
 * rwd: (output) the derived password, DECAF_255_SER_BYTES (32) bytes array
 * returns 1 on error, 0 on success
 */
int sphinx_finish(const uint8_t *pwd, const size_t p_len, const uint8_t *bfac, const uint8_t *resp, uint8_t *rwd) {
  // decode blinding factor into scalar
  decaf_255_scalar_t b;
  decaf_255_scalar_decode_long(b, bfac, DECAF_255_SCALAR_BYTES);

  // calculate 1/x, so we can unblind R
  if(decaf_255_scalar_invert(b, b)!=DECAF_SUCCESS) return 1;

  // decode response into point
  decaf_255_point_t R;
  if(DECAF_SUCCESS!=decaf_255_point_decode(R, resp, DECAF_FALSE)) return 1;

  // unblind the response from the peer: Y=R/x
  decaf_255_point_t Y;
  decaf_255_point_scalarmul(Y, R, b);
  decaf_255_scalar_destroy(b);
  decaf_255_point_destroy(R);

  uint8_t h0[SPHINX_255_SER_BYTES];
  decaf_255_point_encode(h0, Y);
  decaf_255_point_destroy(Y);

  crypto_generichash_state state;
  crypto_generichash_init(&state, 0, 0, 32);
  crypto_generichash_update(&state, pwd, p_len);
  crypto_generichash_update(&state, h0, SPHINX_255_SER_BYTES);
  crypto_generichash_final(&state, rwd, SPHINX_255_SER_BYTES);
  decaf_bzero(&state, sizeof(state));
  decaf_bzero(h0, sizeof(h0));

  return 0;
}
