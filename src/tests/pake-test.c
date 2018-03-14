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
#include "../pake.h"

static void dump(const uint8_t *p, const size_t len, const char* msg) {
  int i;
  printf("%s",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

int main(void) {
  // server setup - only done once in the lifetime of a server
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES],             // server Identity Secret key
    P_s[DECAF_X25519_PUBLIC_BYTES];                    // server Identity pubkey
  opaque_server_init(p_s, P_s);
  // publish P_s widely so all clients have access to it.

  // create user
  uint8_t rwd[32]="                                ";  // FK-PTR output (from sphinx derive), here static for testing only
  Opaque_UserRecord user;                              // output from user init, stored in server.
  opaque_client_init(rwd, sizeof rwd, P_s,             // input params
                     user.k_s, user.c, user.C, user.P_u, user.m_u);

  // user initializes a login session with the server
  uint8_t alpha[32],                                   // blinded rwd to be sent to server
    x_u[32],                                           // users ephemeral secret key
    X_u[32],                                           // users ephemeral pubkey
    p[32];                                             // factor used to blind rwd
  opaque_start_pake(rwd, sizeof rwd,                   // input params
                    alpha, x_u, X_u, p);               // output params

  // server login function
  uint8_t beta[32],
    X_s[32],                                           // servers Ephemeral pubkey
    SK_s[DECAF_X25519_PUBLIC_BYTES];                   // the final result of the PAKE (server-side)
  if(0!=opaque_server_pake(alpha, X_u,                 // these come from start_pake done by the user when trying to login
                           user.k_s, user.P_u,         // comes from user rec stored by the server
                           p_s,                        // is the servers Identity secret key
                           beta, X_s, SK_s)) return 1; // output params

  // finish login sequence and calculate result of PAKE
  uint8_t SK_u[DECAF_X25519_PUBLIC_BYTES];             // final result of the PAKE (user-side)
  if(0!=opaque_user_pake(rwd, sizeof rwd,              // rwd from FK-PTR
                         p,                            // blinding factor from users start_pake
                         x_u,                          // user ephemeral secret key
                         beta,                         // sent from server_pake
                         user.c,                       // sent by server from storage
                         user.C,                       // sent by server from storage
                         user.P_u,                     // sent by server from storage
                         user.m_u,                     // sent by server from storage
                         P_s,                          // servers Identity pubkey
                         X_s,                          // servers Ephemeral pubkey
                         SK_u)) return 2;              // result of the PAKE
  dump(SK_u,32,"SK_u:");
  dump(SK_s,32,"SK_s:");
  return 0;
}
