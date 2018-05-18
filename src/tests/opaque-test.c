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
  uint8_t U[]="user1",
    S[]="server",
    pw[]="simple guessable dictionary password",
    sid[]="user1",
    ssid[]="user1session0";
  Opaque_UserRecord rec;

  // register user
  if(0!=storePwdFile(sid, U, pw, &rec)) return 1;

  // initiate login
  Opaque_UserSession_Secret sec;
  Opaque_UserSession pub;
  usrSession(sid, ssid, pw, &sec, &pub);

  Opaque_ServerSession resp;
  uint8_t sk[32];
  if(0!=srvSession(U, S, &pub, &rec, &resp, sk)) return 1;

  dump(sk,32,"sk_s: ");

  uint8_t pk[32];
  if(0!=userSessionEnd(&resp, &sec, pw, pk)) return 1;

  dump(pk,32,"sk_u: ");

  return 0;
}
