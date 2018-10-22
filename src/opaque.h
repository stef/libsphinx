#ifndef opaque_h
#define opaque_h

#include <stdint.h>
#include <stdlib.h>
#include "decaf.h"
#include <crypto_secretbox.h>

typedef struct {
  uint8_t nonce[crypto_secretbox_NONCEBYTES];
  uint8_t p_u[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t mac[crypto_secretbox_MACBYTES];
} __attribute((packed)) C;

// user specific record stored at server upon registration
typedef struct {
  uint8_t k_s[DECAF_255_SCALAR_BYTES];
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t P_u[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  C c;
} __attribute((packed)) Opaque_UserRecord;

// data sent to S from U in login#1
typedef struct {
  uint8_t alpha[DECAF_X25519_PUBLIC_BYTES];
  uint8_t X_u[DECAF_X25519_PUBLIC_BYTES];
} __attribute((packed)) Opaque_UserSession;

typedef struct {
  uint8_t r[DECAF_X25519_PRIVATE_BYTES];
  uint8_t x_u[DECAF_X25519_PRIVATE_BYTES];
} __attribute((packed)) Opaque_UserSession_Secret;

typedef struct {
  uint8_t beta[DECAF_X25519_PUBLIC_BYTES];
  uint8_t X_s[DECAF_X25519_PUBLIC_BYTES];
  uint8_t salt[32];
  C c;
} __attribute((packed)) Opaque_ServerSession;

typedef struct {
  uint8_t beta[DECAF_X25519_PUBLIC_BYTES];
  uint8_t P_s[DECAF_X25519_PUBLIC_BYTES];
} __attribute((packed)) Opaque_RegisterPub;

typedef struct {
  uint8_t p_s[DECAF_X25519_PRIVATE_BYTES];
  uint8_t k_s[DECAF_X25519_PRIVATE_BYTES];
} __attribute((packed)) Opaque_RegisterSec;

/* 
   This function implements the same function from the paper. This
   function runs on the server and creates a new output record rec of
   secret key material partly encrypted with a key derived from the
   input password pw. The server needs to implement the storage of
   this record and any binding to user names or as the paper suggests
   sid.
 */
int opaque_storePwdFile(const uint8_t *pw, Opaque_UserRecord *rec);

/*
  This function initiates a new OPAQUE session, is the same as the
  function defined in the paper with the same name. The User initiates
  a new session by providing its input password pw, and receving a
  private sec and a "public" pub output parameter. The User should
  protect the sec value until later in the protocol and send the pub
  value over to the Server.
 */
void opaque_usrSession(const uint8_t *pw, Opaque_UserSession_Secret *sec, Opaque_UserSession *pub);

/*
  This is the same function as defined in the paper with the same
  name. It runs on the server and receives the output pub from the
  user running usrSession(), futhermore the server needs to load the
  user record created when registering the user with the
  storePwdFile() function. These input parameters are transformed into
  a secret/shared session key sk and a response resp to be sent back
  to the user.
 */
int opaque_srvSession(const Opaque_UserSession *pub, const Opaque_UserRecord *rec, Opaque_ServerSession *resp, uint8_t *sk);

/*
 This is the same function as defined in the paper with the same
 name. It is run by the user, and recieves as input the response from
 the previous server srvSession() function as well as the sec value
 from running the usrSession() function that initiated this protocol,
 the user password pw is also needed as an input to this final
 step. All these input parameters are transformed into a shared/secret
 session key pk, which should be the same as the one calculated by the
 srvSession() function.
*/
int opaque_userSessionEnd(const Opaque_ServerSession *resp, const Opaque_UserSession_Secret *sec, const uint8_t *pw, uint8_t *pk);

/*
 * This is a simple utility function that can be used to calculate
 * f_k(c), where c is a constant, this is useful if the peers want to
 * authenticate each other.
 */
void opaque_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res);

/* Alternative user initialization
 *
 * The paper originally proposes a very simple 1 shot interface for
 * registering a new "user", however this has the drawback that in
 * that case the users secrets and its password are exposed in
 * cleartext at registration to the server. There is a much less
 * efficient 4 message registration protocol which avoids the exposure
 * of the secrets and the password to the server which can be
 * instantiated by the following for registration functions:
 */


/*
 * The user inputs its password pw, and receives an ephemeral secret r
 * and a blinded value alpha as output. r should be protected until
 * step 3 of this registration protocol and the value alpha should be
 * passed to the server.
 */
void opaque_newUser(const uint8_t *pw, uint8_t *r, uint8_t *alpha);

/*
 * The server receives alpha from the users invocation of its
 * newUser() function, it outputs a value sec which needs to be
 * protected until step 4 by the server. This function also outputs a
 * value pub which needs to be passed to the user.
 */
int opaque_initUser(const uint8_t *alpha, Opaque_RegisterSec *sec, Opaque_RegisterPub *pub);

/*
 * This function is run by the user, taking as input the users
 * password pw, the ephemeral secret r that was an output of the user
 * running newUser(), and the output pub from the servers run of
 * initUser(). The result of this is the value rec which should be
 * passed for the last step to the server.
 */
int opaque_registerUser(const uint8_t *pw, const uint8_t *r, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);

/*
 * The server combines the sec value from its run of its initUser()
 * function with the rec output of the users registerUser() function,
 * creating the final record, which should be the same as the output
 * of the 1-step storePwdFile() init function of the paper. The server
 * should save this record in combination with a user id and/or sid
 * value as suggested in the paper.
 */
void opaque_saveUser(const Opaque_RegisterSec *sec, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);

#endif // opaque_h
