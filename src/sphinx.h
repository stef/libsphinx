#ifndef sphinx_h
#define sphinx_h

#include <stdint.h>
#include <stdlib.h>
#include "decaf.h"

void challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal);
int respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp);
int finish(const uint8_t *bfac, const uint8_t *resp, uint8_t *rwd);

#endif // sphinx_h
