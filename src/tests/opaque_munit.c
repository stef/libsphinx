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

#define MUNIT_ENABLE_ASSERT_ALIASES
#include "munit/munit.h"

#include <stdio.h>
#include "../opaque.h"
#include "../common.h"

static char* pw_params[] = {
  "simple guessable dictionary password",
  "1",
  "",
  NULL
};

static char* key_params[] = {
  "some optional key contributed to the opaque protocol",
  "1",
  "",
  NULL
};

static char* idU_params[] = {
  "xxxxxxxxxxxxxxxxxxxxxxxx",
  "user",
  "",
  NULL
};

static char* idS_params[] = {
  "xxxxxxxxxxxxxxxxxxxxxxxx",
  "server",
  "",
  NULL
};

static char* cfg_params[]=
  {"\x04",
   "\x44",
   "\x84",
   "\x14",
   "\x54",
   "\x94",
   "\x24",
   "\x64",
   "\xa4",
   "\x08",
   "\x48",
   "\x88",
   "\x18",
   "\x58",
   "\x98",
   "\x28",
   "\x68",
   "\xa8",
   "\x05",
   "\x45",
   "\x85",
   "\x15",
   "\x55",
   "\x95",
   "\x25",
   "\x65",
   "\xa5",
   "\x09",
   "\x49",
   "\x89",
   "\x19",
   "\x59",
   "\x99",
   "\x29",
   "\x69",
   "\xa9",
   "\x06",
   "\x46",
   "\x86",
   "\x16",
   "\x56",
   "\x96",
   "\x26",
   "\x66",
   "\xa6",
   "\x0a",
   "\x4a",
   "\x8a",
   "\x1a",
   "\x5a",
   "\x9a",
   "\x2a",
   "\x6a",
   "\xaa",
   NULL
};

static MunitParameterEnum init_params[] = {
  { "pw", pw_params },
  { "key", key_params },
  { "idU", idU_params },
  { "idS", idS_params },
  { "cfg", cfg_params },
  { NULL, NULL },
};

MunitResult server_init(const MunitParameter params[], void* user_data_or_fixture) {
  (void)user_data_or_fixture;
  const uint8_t *pw=(const uint8_t*) munit_parameters_get(params, "pw"); //"simple guessable dictionary password";
  const size_t pwlen=strlen((char*) pw);
  const uint8_t *key=(const uint8_t*) munit_parameters_get(params, "key");;
  size_t key_len=strlen((char*) key);
  uint8_t export_key[crypto_hash_sha256_BYTES];
  uint8_t export_key_x[crypto_hash_sha256_BYTES];

  Opaque_Ids ids={0, (uint8_t*) munit_parameters_get(params, "idU"),
                  0, (uint8_t*) munit_parameters_get(params, "idS")};
  ids.idU_len = strlen((char*)ids.idU);
  ids.idS_len = strlen((char*)ids.idS);

  Opaque_PkgConfig *cfg=(Opaque_PkgConfig *) munit_parameters_get(params, "cfg");
  fprintf(stderr, "cfg pku:%d, pks:%d, idu:%d, ids:%d\n", cfg->pkU, cfg->pkS, cfg->idU, cfg->idS);

  const uint16_t ClrEnv_len = package_len(cfg, &ids, InClrEnv);
  const uint16_t SecEnv_len = package_len(cfg, &ids, InSecEnv);
  const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
  unsigned char rec[OPAQUE_USER_RECORD_LEN+env_len];
  fprintf(stderr,"sizeof(rec): %ld\n",sizeof(rec));

  // register user
  fprintf(stderr,"opaque_init_srv()\n");
  if(0!=opaque_init_srv(pw, pwlen, key, key_len, cfg, &ids, rec, export_key)) return MUNIT_FAIL;

  // initiate login
  unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN+pwlen], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  fprintf(stderr,"opaque_session_usr_start()\n");
  opaque_session_usr_start(pw, pwlen, sec, pub);

  unsigned char resp[OPAQUE_SERVER_SESSION_LEN+env_len];
  uint8_t sk[32];
  Opaque_ServerAuthCTX ctx={0};
  fprintf(stderr,"opaque_session_srv()\n");
  if(0!=opaque_session_srv(pub, rec, &ids, NULL, resp, sk, &ctx)) return MUNIT_FAIL;

  uint8_t pk[32];
  fprintf(stderr,"opaque_session_usr_finish()\n");
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t idU[ids.idU_len], idS[ids.idS_len]; // must be big enough to fit ids
  Opaque_Ids ids1={sizeof idU,idU,sizeof idS,idS};
  // in case we omit the id* in the envelope we must provide it before-hand.
  // if it is in the envelope it will be populated from the envelope
  if(cfg->idU == NotPackaged) {
    ids1.idU_len = ids.idU_len;
    memcpy(idU, ids.idU, ids.idU_len);
  }
  if(cfg->idS == NotPackaged) {
    ids1.idS_len = ids.idS_len;
    memcpy(idS, ids.idS, ids.idS_len);
  }
  //Opaque_App_Infos infos;
  if(0!=opaque_session_usr_finish(resp, sec, key, key_len, cfg, NULL, &ids1, pk, authU, export_key_x)) return MUNIT_FAIL;
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);
  assert(sodium_memcmp(export_key,export_key_x,sizeof export_key)==0);

  fprintf(stderr,"opaque_session_server_auth()\n");
  if(-1==opaque_session_server_auth(&ctx, authU, NULL)) {
    fprintf(stderr,"failed authenticating user\n");
    return MUNIT_FAIL;
  }
  return MUNIT_OK;
}

MunitResult private_init(const MunitParameter params[], void* user_data_or_fixture) {
  // variant where user registration does not leak secrets to server
  (void)user_data_or_fixture;
  const uint8_t *pw=(const uint8_t*) munit_parameters_get(params, "pw"); //"simple guessable dictionary password";
  size_t pwlen=strlen((char*) pw);
  const uint8_t *key=(const uint8_t*) munit_parameters_get(params, "key");;
  size_t key_len=strlen((char*) key);
  uint8_t export_key[crypto_hash_sha256_BYTES];
  Opaque_Ids ids={0,
                  (uint8_t*) munit_parameters_get(params, "idU"),
                  0,
                  (uint8_t*) munit_parameters_get(params, "idS")};
  ids.idU_len = strlen((char*)ids.idU);
  ids.idS_len = strlen((char*)ids.idS);
  Opaque_PkgConfig *cfg=(Opaque_PkgConfig *) munit_parameters_get(params, "cfg");
  const uint16_t ClrEnv_len = package_len(cfg, &ids, InClrEnv);
  const uint16_t SecEnv_len = package_len(cfg, &ids, InSecEnv);
  const uint32_t env_len = OPAQUE_ENVELOPE_META_LEN + SecEnv_len + ClrEnv_len;
  unsigned char rec[OPAQUE_USER_RECORD_LEN+env_len];
  unsigned char sec[OPAQUE_USER_SESSION_SECRET_LEN+pwlen], pub[OPAQUE_USER_SESSION_PUBLIC_LEN];
  unsigned char resp[OPAQUE_SERVER_SESSION_LEN+env_len];
  uint8_t sk[32];
  uint8_t pk[32];
  uint8_t authU[crypto_auth_hmacsha256_BYTES];
  uint8_t idU[ids.idU_len], idS[ids.idS_len]; // must be big enough to fit ids
  Opaque_Ids ids1={sizeof idU,idU,sizeof idS,idS};
  // in case we omit the id* in the envelope we must provide it before-hand.
  // if it is in the envelope it will be populated from the envelope
  if(cfg->idU == NotPackaged) {
    ids1.idU_len = ids.idU_len;
    memcpy(idU, ids.idU, ids.idU_len);
  }
  if(cfg->idS == NotPackaged) {
    ids1.idS_len = ids.idS_len;
    memcpy(idS, ids.idS, ids.idS_len);
  }
  Opaque_ServerAuthCTX ctx;

  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t r[crypto_core_ristretto255_SCALARBYTES];
  // user initiates:
  fprintf(stderr,"opaque_private_init_usr_start\n");
  if(0!=opaque_private_init_usr_start(pw, pwlen, r, alpha)) return MUNIT_FAIL;
  // server responds
  unsigned char rsec[OPAQUE_REGISTER_SECRET_LEN], rpub[OPAQUE_REGISTER_PUBLIC_LEN];
  fprintf(stderr,"opaque_private_init_srv_respond\n");
  if(0!=opaque_private_init_srv_respond(alpha, rsec, rpub)) return MUNIT_FAIL;
  // user commits its secrets
  fprintf(stderr,"opaque_private_init_usr_respond\n");
  if(0!=opaque_private_init_usr_respond(pw, pwlen, r, rpub, key, key_len, cfg, &ids, rec, export_key)) return MUNIT_FAIL;
  // server "saves"
  fprintf(stderr,"opaque_private_init_srv_finish\n");
  opaque_private_init_srv_finish(rsec, rpub, rec);

  fprintf(stderr,"opaque_session_usr_start\n");
  opaque_session_usr_start(pw, pwlen, sec, pub);
  fprintf(stderr,"opaque_session_srv\n");
  if(0!=opaque_session_srv(pub, rec, &ids, NULL, resp, sk, &ctx)) return MUNIT_FAIL;
  fprintf(stderr,"opaque_session_usr_finish\n");
  if(0!=opaque_session_usr_finish(resp, sec, key, key_len, cfg, NULL, &ids1, pk, authU, export_key)) return MUNIT_FAIL;
  assert(sodium_memcmp(sk,pk,sizeof sk)==0);

  // authenticate both parties:
  if(-1==opaque_session_server_auth(&ctx, authU, NULL)) {
    fprintf(stderr,"failed authenticating user\n");
    return MUNIT_FAIL;
  }

  printf("all ok\n");

  return MUNIT_OK;
}

MunitTest tests[] = {
  { "/server-init", /* name */
    server_init, /* test */
    NULL, /* setup */
    NULL, /* tear_down */
    MUNIT_TEST_OPTION_NONE, /* options */
    init_params /* parameters */
  },
  { "/private-init", /* name */
    private_init, /* test */
    NULL, /* setup */
    NULL, /* tear_down */
    MUNIT_TEST_OPTION_NONE, /* options */
    init_params /* parameters */
  },
  /* Mark the end of the array with an entry where the test
   * function is NULL */
  { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL }
};

static const MunitSuite suite = {
  "/opaque-tests",
  tests, /* tests */
  NULL, /* suites */
  1, /* iterations */
  MUNIT_SUITE_OPTION_NONE /* options */
};

int main (int argc, char* const argv[]) {
   return munit_suite_main(&suite, NULL, argc, argv);
}
