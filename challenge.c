#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <decaf.h>
#include <randombytes.h>
#include <crypto_generichash.h>

int main(void) {
  // hash the master password from stdin

  crypto_generichash_state state;
  unsigned char hash[DECAF_255_HASH_BYTES];
  crypto_generichash_init(&state, 0, 0, sizeof hash);

  uint8_t buf[32768]; // 32KB blocks
  int size;
  while(!feof(stdin)) {
    size=fread(buf, 1, 32768, stdin);
    crypto_generichash_update(&state, buf, size);
  }
  crypto_generichash_final(&state, hash, sizeof hash);

  // hashed_to_point with elligator the password hash
  decaf_255_point_t P;
  decaf_255_point_from_hash_nonuniform(P, hash);

  // generate random blinding factor
  unsigned char blinder[DECAF_255_SCALAR_BYTES];
  randombytes(blinder, sizeof(blinder)); // random blinding factor

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

  // convert the blinding factor into a scalar
  decaf_255_scalar_t b;
  decaf_255_scalar_decode_long(b, blinder, sizeof(blinder));

  // blind the message: C=Pb
  decaf_255_point_t challenge;
  decaf_255_point_scalarmul(challenge, P, b);

  // serialize the challenge
  uint8_t out[DECAF_255_SER_BYTES];
  decaf_255_point_encode(out, challenge);

  // output the challenge
  int i;
  for(i=0;i<sizeof(out);i++) {
    printf("%c",out[i]);
  }

  return 0;
}
