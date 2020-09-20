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
#include <assert.h>
#include "../opaque.h"
#include "../common.h"

static void _dump(const uint8_t *p, const size_t len, const char* msg) {
  size_t i;
  printf("%s",msg);
  for(i=0;i<len;i++)
    printf("%02x", p[i]);
  printf("\n");
}

int main(void) {
  uint8_t pw[]="simple guessable dictionary password";
  size_t pwlen=strlen((char*) pw);
  uint8_t key[]="some optional key contributed to the opaque protocol";
  size_t key_len=strlen((char*) key);
  uint8_t export_key[crypto_hash_sha256_BYTES];
  uint8_t export_key_x[crypto_hash_sha256_BYTES];
  Opaque_Ids ids={4,(uint8_t*)"user",6,(uint8_t*)"server"};
  ids.idU_len = strlen((char*) ids.idU);
  ids.idS_len = strlen((char*) ids.idS);
  Opaque_PkgConfig cfg={
                        .pkU = NotPackaged,
                        .pkS = InClrEnv,
                        .idS = NotPackaged,
                        .idU = NotPackaged,
  };
  _dump((uint8_t*) &cfg,sizeof cfg, "cfg ");
  const uint16_t ClrEnv_len = package_len(&cfg, &ids, InClrEnv);
  const uint16_t SecEnv_len = package_len(&cfg, &ids, InSecEnv);
  const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
  unsigned char rec[OPAQUE_USER_RECORD_LEN+env_len];
  printf("sizeof(rec): %ld\n",sizeof(rec));

  // register user
  printf("opaque_init_srv()\n");
  if(0!=opaque_init_srv(pw, pwlen, key, key_len, &cfg, &ids, rec, export_key)) return 1;

  // initiate login
  unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN+pwlen], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  printf("opaque_session_usr_start()\n");
  opaque_session_usr_start(pw, pwlen, sec, pub);

  unsigned char resp[OPAQUE_SERVER_SESSION_LEN+env_len];
  uint8_t sk[32];
  Opaque_ServerAuthCTX ctx;
  printf("opaque_session_srv()\n");
  if(0!=opaque_session_srv(pub, rec, &ids, NULL, resp, sk, &ctx)) return 1;

  _dump(sk,32,"sk_s: ");

  uint8_t pk[32];
  printf("opaque_session_usr_finish()\n");
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t idU[ids.idU_len], idS[ids.idS_len]; // must be big enough to fit ids
  Opaque_Ids ids1={sizeof idU,idU, sizeof idS ,idS};
  if(cfg.idU == NotPackaged) {
    ids1.idU_len = ids.idU_len;
    memcpy(idU, ids.idU, ids.idU_len);
  }
  if(cfg.idS == NotPackaged) {
    ids1.idS_len = ids.idS_len;
    memcpy(idS, ids.idS, ids.idS_len);
  }
  //Opaque_App_Infos infos;
  if(0!=opaque_session_usr_finish(resp, sec, key, key_len, &cfg, NULL, &ids1, pk, authU, export_key_x)) return 1;
  _dump(pk,32,"sk_u: ");
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);
  assert(sodium_memcmp(export_key,export_key_x,sizeof export_key)==0);

  printf("opaque_session_server_auth()\n");
  if(-1==opaque_session_server_auth(&ctx, authU, NULL)) {
    printf("failed authenticating user\n");
    return 1;
  }

  printf("\nprivate registration\n\n");

  // variant where user registration does not leak secrets to server
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t usr_ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwlen];
  // user initiates:
  printf("opaque_private_init_usr_start\n");
  if(0!=opaque_private_init_usr_start(pw, pwlen, usr_ctx, alpha)) return 1;
  // server responds
  unsigned char rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
  printf("opaque_private_init_srv_respond\n");
  if(0!=opaque_private_init_srv_respond(alpha, rsec, rpub)) return 1;
  // user commits its secrets
  unsigned char rrec[OPAQUE_USER_RECORD_LEN+env_len];
  printf("opaque_private_init_usr_respond\n");
  if(0!=opaque_private_init_usr_respond(usr_ctx, rpub, key, key_len, &cfg, &ids, rrec, export_key)) return 1;
  // server "saves"
  printf("opaque_private_init_srv_finish\n");
  opaque_private_init_srv_finish(rsec, rpub, rrec);

  printf("opaque_session_usr_start\n");
  opaque_session_usr_start(pw, pwlen, sec, pub);
  printf("opaque_session_srv\n");
  if(0!=opaque_session_srv(pub, rrec, &ids, NULL, resp, sk, &ctx)) return 1;
  _dump(sk,32,"sk_s: ");
  printf("opaque_session_usr_finish\n");
  if(0!=opaque_session_usr_finish(resp, sec, key, key_len, &cfg, NULL, &ids1, pk, authU, export_key)) return 1;
  _dump(pk,32,"sk_u: ");
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:

  if(-1==opaque_session_server_auth(&ctx, authU, NULL)) {
    printf("failed authenticating user\n");
    return 1;
  }

  printf("all ok\n");

  return 0;
}

