#include "../sphinx.h"
#include <stdio.h>
#include <stdint.h>

int main(void) {
  const uint8_t pwd[]="shitty password";
  const uint8_t secret[SPHINX_255_SCALAR_BYTES]="                                ";
  uint8_t bfac[SPHINX_255_SCALAR_BYTES],
    chal[SPHINX_255_SER_BYTES],
    resp[SPHINX_255_SER_BYTES],
    rwd[SPHINX_255_SER_BYTES];

  sphinx_challenge(pwd, sizeof pwd, bfac, chal);
  if(0!=sphinx_respond(chal, secret, resp)) {
    return 1;
  }
  if(0!=sphinx_finish(pwd, sizeof pwd, bfac, resp, rwd)) {
    return 1;
  }

  unsigned i;
  for(i=0;i<sizeof rwd;i++) {
    printf("%02x",rwd[i]);
  }
  printf("\n");

  return 0;
}
