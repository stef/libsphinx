/*
    @copyright 2018-2021, sphinx@ctrlc.hu
    This file is part of libsphinx.

    SPDX-FileCopyrightText: 2018-21, Stefan Marsiske
    SPDX-License-Identifier: LGPL-3.0-or-later

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
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sodium.h>

int main(void) {
  // hash the master password from stdin

  crypto_generichash_state state;
  uint8_t hash[crypto_core_ristretto255_HASHBYTES];
  // hash x with H0
  crypto_generichash_init(&state, 0, 0, sizeof hash);

  uint8_t buf[32768]; // 32KB blocks
  int size;
  while(!feof(stdin)) {
    size=fread(buf, 1, 32768, stdin);
    crypto_generichash_update(&state, buf, size);
  }
  crypto_generichash_final(&state, hash, sizeof hash);

  // hash x with H0
  unsigned char H0[crypto_core_ristretto255_BYTES];
  crypto_core_ristretto255_from_hash(H0, hash);

  // blinding factor
  unsigned char blinder[crypto_core_ristretto255_SCALARBYTES];
  crypto_core_ristretto255_scalar_random(blinder);

  // persist the blinding factor
  char fname[]="/tmp/sphinxXXXXXX";
  int fd = mkstemp(fname);
  if(fd==-1) {
    fprintf(stderr, "failed to open temp file to persist blinding factor\nabort.\n");
    return 1;
  }
  if(write(fd, blinder, sizeof blinder)!=sizeof blinder) {
    fprintf(stderr,"failed to persist blinding factor\nabort.\n");
    return 1;
  }
  close(fd);
  fprintf(stderr,"%s",fname);

  unsigned char challenge[crypto_core_ristretto255_BYTES];
  if (crypto_scalarmult_ristretto255(challenge, blinder, H0) != 0) {
    return -1;
  }

  // output the challenge
  size_t i;
  for(i=0;i<sizeof(challenge);i++) {
    printf("%c",challenge[i]);
  }

  return 0;
}
