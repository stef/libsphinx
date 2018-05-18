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
#include <string.h>
#include "../opaque.h"

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  int i;
  printf("%s",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

int main(void) {
  uint8_t pw[]="simple guessable dictionary password";
  Opaque_UserRecord rec;

  // register user
  if(0!=opaque_storePwdFile(pw, &rec)) return 1;

  // initiate login
  Opaque_UserSession_Secret sec;
  Opaque_UserSession pub;
  opaque_usrSession(pw, &sec, &pub);

  Opaque_ServerSession resp;
  uint8_t sk[32];
  if(0!=opaque_srvSession(&pub, &rec, &resp, sk)) return 1;

  dump(sk,32,"sk_s: ");

  uint8_t pk[32];
  if(0!=opaque_userSessionEnd(&resp, &sec, pw, pk)) return 1;

  dump(pk,32,"sk_u: ");
  if(memcmp(sk,pk,sizeof sk)!=0) return 1;

  // variant where user registration does not leak secrets to server
  uint8_t alpha[DECAF_X25519_PUBLIC_BYTES];
  uint8_t r[DECAF_X25519_PRIVATE_BYTES];
  // user initiates:
  opaque_newUser(pw, r, alpha);
  // server responds
  Opaque_RegisterSec rsec;
  Opaque_RegisterPub rpub;
  if(0!=opaque_initUser(alpha, &rsec, &rpub)) return 1;
  // user commits its secrets
  Opaque_UserRecord rrec;
  if(0!=opaque_registerUser(pw, r, &rpub, &rrec)) return 1;
  // server "saves"
  opaque_saveUser(&rsec, &rpub, &rrec);

  opaque_usrSession(pw, &sec, &pub);
  if(0!=opaque_srvSession(&pub, &rec, &resp, sk)) return 1;
  dump(sk,32,"sk_s: ");
  if(0!=opaque_userSessionEnd(&resp, &sec, pw, pk)) return 1;
  dump(pk,32,"sk_u: ");
  if(memcmp(sk,pk,sizeof sk)!=0) return 1;

  // authenticate both parties:

  // to authenticate the server to the user, the server sends f_sk(1)
  // to the user, which calculates f_pk(1) and verifies it's the same
  // value as sent by the server.
  uint8_t su[32], us[32];
  opaque_f(sk, sizeof sk, 1, su);
  opaque_f(pk, sizeof pk, 1, us);
  dump(su, 32, "f_sk(1): ");
  dump(us, 32, "f_pk(1): ");
  if(0!=memcmp(su,us,32)) return 1;

  // to authenticate the user to the server, the user sends f_pk(2)
  // to the server, which calculates f_sk(2) and verifies it's the same
  // value as sent by the user.
  opaque_f(pk, sizeof pk, 2, us);
  opaque_f(sk, sizeof sk, 2, su);
  dump(us, 32, "f_pk(2): ");
  dump(su, 32, "f_sk(2): ");
  if(0!=memcmp(su,us,32)) return 1;

  return 0;
}
