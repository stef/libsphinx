/*
    @copyright 2018-2021, sphinx@ctrlc.hu
    This file is part of libsphinx.

    libsphinx is free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libsphinx is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libsphinx. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <sodium.h>

int main(int argc, char **argv) {
  (void) argc;
  uint8_t blind[crypto_core_ristretto255_SCALARBYTES],
    resp[crypto_core_ristretto255_BYTES];

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

  // invert r = 1/r
  unsigned char ir[crypto_core_ristretto255_SCALARBYTES];
  if (crypto_core_ristretto255_scalar_invert(ir, blind) != 0) {
    return -1;
  }

  // beta^(1/r) = h(pwd)^k
  unsigned char H0_k[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(H0_k, ir, resp) != 0) {
    return -1;
  }

  // hash(pwd||H0^k)
  crypto_generichash_state state;
  uint8_t out[32];
  // hash x with H0
  crypto_generichash_init(&state, 0, 0, sizeof out);

  uint8_t buf[32768]; // 32KB blocks
  int size;
  while(!feof(stdin)) {
    size=fread(buf, 1, 32768, stdin);
    crypto_generichash_update(&state, buf, size);
  }
  crypto_generichash_update(&state, H0_k, sizeof H0_k);
  crypto_generichash_final(&state, out, 32);

  size_t i;
  for(i=0;i<sizeof(out);i++) {
    printf("%02x",out[i]);
  }
  printf("\n");

  unlink(argv[1]);

  return 0;
}
