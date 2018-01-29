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

int main(int argc, char** argv) {
  uint8_t challenge[DECAF_255_SER_BYTES],
    secret[DECAF_255_SCALAR_BYTES];

  // read challenge from stdin
  if(fread(challenge, 32, 1, stdin)!=1) {
    fprintf(stderr, "expected 32B challenge on stdin\n");
    return 1;
  }

  // read secret key from file passed in argv[1]
  FILE *f = fopen(argv[1], "r");
  if(f==NULL) {
    fprintf(stderr,"could not open %s\n", argv[1]);
    return 1;
  }
  if(fread(secret, 32, 1, f)!=1) {
    fprintf(stderr, "expected 32B secret in %s\n", argv[1]);
    return 1;
  }
  fclose(f);

  // deserialize challenge into C
  decaf_255_point_t C, R;
  if(DECAF_SUCCESS!=decaf_255_point_decode(C, challenge, DECAF_FALSE)) return 1;

  // peer contributes their own secret: R=Cy
  decaf_255_scalar_t key;
  decaf_255_scalar_decode_long(key, secret, sizeof(secret));
  decaf_255_point_scalarmul(R, C, key);

  // serialize R into out
  unsigned char out[DECAF_255_SER_BYTES];
  decaf_255_point_encode(out, R);

  // output the response
  int i;
  for(i=0;i<sizeof(out);i++) {
    printf("%c",out[i]);
  }

  return 0;
}
