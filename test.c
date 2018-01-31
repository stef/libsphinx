#include "sphinx.h"
#include <stdio.h>
#include <stdint.h>

int main(void) {
  const uint8_t pwd[]="shitty password";
  const uint8_t secret[DECAF_255_SCALAR_BYTES]="                                ";
  uint8_t bfac[DECAF_255_SCALAR_BYTES],
    chal[DECAF_255_SER_BYTES],
    resp[DECAF_255_SER_BYTES],
    rwd[DECAF_255_SER_BYTES];

  challenge(pwd, sizeof pwd, bfac, chal);
  if(0!=respond(chal, secret, resp)) {
    return 1;
  }
  if(0!=finish(bfac, resp, rwd)) {
    return 1;
  }

  int i;
  for(i=0;i<sizeof rwd;i++) {
    printf("%02x",rwd[i]);
  }
  printf("\n");

  return 0;
}
