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
#include <unistd.h>
#include <decaf.h>

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

int main(int argc, char **argv) {
  uint8_t blind[DECAF_255_SCALAR_BYTES],
    resp[DECAF_255_SER_BYTES];

  // read response from stdin
  if(fread(resp, 32, 1, stdin)!=1) {
    fprintf(stderr, "expected 32B response on stdin\n");
    return 1;
  }

  // read blinding factor from file passed in argv[1]
  FILE *f = fopen(argv[1], "r");
  if(f==NULL) {
    fprintf(stderr,"could not open %s\n", argv[1]);
    return 1;
  }
  if(fread(blind, 32, 1, f)!=1) {
    fprintf(stderr, "expected 32B blinding factor in %s\n", argv[1]);
    return 1;
  }
  fclose(f);

  // decode blinding factor into scalar
  decaf_255_scalar_t b;
  decaf_255_scalar_decode_long(b, blind, sizeof(blind));

  // calculate 1/x, so we can unblind R
  if(decaf_255_scalar_invert(b, b)!=DECAF_SUCCESS) return 1;

  // decode response into point
  decaf_255_point_t R;
  if(DECAF_SUCCESS!=decaf_255_point_decode(R, resp, DECAF_FALSE)) return 1;

  // unblind the response from the peer: Y1=R/x
  decaf_255_point_t Y;
  decaf_255_point_scalarmul(Y, R, b);


  unsigned char out[DECAF_255_SER_BYTES];
  decaf_255_point_encode(out, Y);
  // output the response

  int i;
  for(i=0;i<sizeof(out);i++) {
    printf("%02x",out[i]);
  }
  printf("\n");

  unlink(argv[1]);

  return 0;
}
