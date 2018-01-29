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
#include <stdio.h>
#include <decaf.h>
#include <randombytes.h>
#include <crypto_generichash.h>

void dump(const decaf_255_point_t pt, char* m) {
  int i;
  uint8_t ser[DECAF_255_SER_BYTES];
  decaf_255_point_encode(ser, pt);

  printf("%s", m);
  for(i=0;i<sizeof(ser);i++) {
    printf("%02x",ser[i]);
  }
  printf("\n");
}

int main(void) {
  unsigned char m[]="shitty master password", x[32], y[32];
  randombytes(x, sizeof(x)); // blinding factor
  randombytes(y, sizeof(y)); // the pitchfork secret

  // the message to be blinded - hashed_to_point with elligator
  unsigned char hash[DECAF_255_HASH_BYTES];
  crypto_generichash(hash, sizeof hash, m, sizeof m, 0, 0);
  decaf_255_point_t M;
  decaf_255_point_from_hash_nonuniform(M, hash);

  // what is the expected value: Y=My
  //if(crypto_scalarmult(Y,M,y)!=0) return 1;
  decaf_255_scalar_t tmp;
  decaf_255_point_t Y;
  decaf_255_scalar_decode_long(tmp, y, sizeof(y));
  decaf_255_point_scalarmul(Y, M, tmp);

  // simulate blinded protocol

  // blind the message: X=Mx
  decaf_255_point_t X;
  decaf_255_scalar_decode_long(tmp, x, sizeof(x));
  decaf_255_point_scalarmul(X, M, tmp);

  dump(X,"X: ");
  printf("y: ");
  int i;
  for(i=0;i<sizeof(y);i++) {
    printf("%02x",y[i]);
  }
  printf("\n");
  // peer contributes their own secret: R=Xy
  decaf_255_point_t R;
  decaf_255_scalar_decode_long(tmp, y, sizeof(y));
  decaf_255_point_scalarmul(R, X, tmp);

  dump(R,"R: ");

  // calculate 1/x, so we can unblind R
  decaf_255_scalar_decode_long(tmp, x, sizeof(x));
  if(decaf_255_scalar_invert(tmp, tmp)!=DECAF_SUCCESS) return 1;

  // unblind the response from the peer: Y1=R/x
  decaf_255_point_t Y1;
  decaf_255_point_scalarmul(Y1, R, tmp);

  // Y1 should be equal Y
  dump(Y,"Y: ");
  dump(Y1,"Y1:");
  printf("Y==Y1 is %d\n", DECAF_TRUE==decaf_255_point_eq(Y1,Y));

  return 0;
}
