/**
 *  @file opaque.h
 */

#ifndef opaque_h
#define opaque_h

#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#define OPAQUE_NONCE_BYTES 32

#define OPAQUE_ENVELOPE_META_LEN (2*crypto_hash_sha256_BYTES + 2*sizeof(uint16_t))

#define OPAQUE_USER_RECORD_LEN (                       \
   /* k_s */ crypto_core_ristretto255_SCALARBYTES+     \
   /* p_s */ crypto_scalarmult_SCALARBYTES+            \
   /* P_u */ crypto_scalarmult_BYTES+                  \
   /* P_s */ crypto_scalarmult_BYTES+                  \
   /* env_len */ sizeof(uint32_t))

#define OPAQUE_USER_SESSION_PUBLIC_LEN (               \
   /* alpha */  crypto_core_ristretto255_BYTES+        \
   /* X_u */    crypto_scalarmult_BYTES+               \
   /* nonceU */ OPAQUE_NONCE_BYTES)

#define OPAQUE_USER_SESSION_SECRET_LEN (               \
   /* r */      crypto_core_ristretto255_SCALARBYTES+  \
   /* x_u */    crypto_scalarmult_SCALARBYTES+         \
   /* nonceU */ OPAQUE_NONCE_BYTES+                    \
   /* alpha */  crypto_core_ristretto255_BYTES+        \
   /* pw_len */ sizeof(uint32_t))

#define OPAQUE_SERVER_SESSION_LEN (                    \
   /* beta */ crypto_core_ristretto255_BYTES+          \
   /* X_s */ crypto_scalarmult_BYTES+                  \
   /* nonceS */ OPAQUE_NONCE_BYTES+                    \
   /* auth */ crypto_auth_hmacsha256_BYTES+            \
   /* env_len */ sizeof(uint32_t))

#define OPAQUE_REGISTER_PUBLIC_LEN (                   \
   /* beta */ crypto_core_ristretto255_BYTES+          \
   /* P_s */ crypto_scalarmult_BYTES)

#define OPAQUE_REGISTER_SECRET_LEN (                   \
   /* p_s */ crypto_scalarmult_SCALARBYTES+            \
   /* k_s */ crypto_core_ristretto255_SCALARBYTES)

#define OPAQUE_REGISTER_USER_SEC_LEN (                 \
   /* r */ crypto_scalarmult_BYTES+                    \
   sizeof(size_t))

#define OPAQUE_SERVER_AUTH_CTX_LEN ( \
  crypto_auth_hmacsha256_KEYBYTES +  \
  sizeof(crypto_hash_sha256_state))

/**
   struct to store the IDs of the user/server.
 */
typedef struct {
  uint16_t idU_len;    /**< length of idU, most useful if idU is binary */
  uint8_t *idU;        /**< pointer to the id of the user/client in the opaque protocol */
  uint16_t idS_len;    /**< length of idS, needed for binary ids */
  uint8_t *idS;        /**< pointer to the id of the server in the opaque protocol */
} Opaque_Ids;

/**
   struct to store various extra protocol information.

   This is defined by the RFC to be used to bind extra
   session-specific parameters to the current session.
*/
typedef struct {
  uint8_t *info1;
  size_t info1_len;
  uint8_t *info2;
  size_t info2_len;
  uint8_t *einfo2;
  size_t einfo2_len;
  uint8_t *info3;
  size_t info3_len;
  uint8_t *einfo3;
  size_t einfo3_len;
} Opaque_App_Infos;

/**
 * enum to define the handling of various fields packed in the opaque envelope
 */
typedef enum {
  NotPackaged = 0,
  InSecEnv = 1,     /**< field is encrypted */
  InClrEnv = 2      /**< field is plaintext, but authenticated */
} __attribute((packed)) Opaque_PkgTarget;

/**
 * configuration of the opaque envelope fields
 */
typedef struct {
  Opaque_PkgTarget pkU : 2;  /**< users public key - if not included
                                it can be derived from the private
                                key */
  Opaque_PkgTarget pkS : 2;  /**< servers public key - currently this
                                is not allowed to set to NotPackaged -
                                TODO if set to NotPackaged allow to
                                specify the pubkey explicitly as a
                                param to the functions that require
                                this info */
  Opaque_PkgTarget idU : 2;  /**< id of the user - the RFC specifies
                                this to be possible to pack into the
                                envelope */
  Opaque_PkgTarget idS : 2;  /**< id of the server - the RFC specifies
                                this to be possible to pack into the
                                envelope */
} Opaque_PkgConfig;

/**
   This function implements the storePwdFile function from the paper
   it is not specified by the RFC. This function runs on the server
   and creates a new output record rec of secret key material. The
   server needs to implement the storage of this record and any
   binding to user names or as the paper suggests sid.

   @param [in] pw - the users password
   @param [in] pwlen - length of the users password
   @param [in] key - a key to be used for domain separation in the
        final hash of the OPRF. if set to NULL then the default is
        "RFCXXXX" - TODO set XXXX to the real value when the rfc is
        published.
   @param [in] key_len - length of the key, ignored if key is NULL
   @param [in] sk - in case of global server keys this is the servers
        private key, should be set to NULL if per/user keys are to be
        generated
   @param [in] cfg - configuration of the opaque envelope, see
        Opaque_PkgConfig
   @param [in] ids - the ids of the user and server, see Opaque_Ids
   @param [out] rec - the opaque record the server needs to
        store. this is a pointer to memory allocated by the caller,
        and must be large enough to hold the record and take into
        account the variable length of idU and idS in case these are
        included in the envelope.
   @param [out] export_key - optional pointer to pre-allocated (and
        protected) memory for an extra_key that can be used to
        encrypt/authenticate additional data.
   @return the function returns 0 if everything is correct
 */
int opaque_init_srv(const uint8_t *pw, const size_t pwlen, const uint8_t *key, const uint64_t key_len, const uint8_t sk[crypto_scalarmult_SCALARBYTES], const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   This function initiates a new OPAQUE session, is the same as the
   function defined in the paper with the name usrSession and in the
   rfc with the name CreateCredentialRequest.

   @param [in] pw - users input password
   @param [in] pwlen - length of the users password
   @param [out] sec - private context, The User should protect the sec
        value (e.g. with sodium_mlock()) until
   @param [out] pub - the message to be sent to the server
   @return the function returns 0 if everything is correct
 */
int opaque_session_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN]);

/**
   This is the same function as defined in the paper with name
   srvSession name and in the rfc it is called
   CreateCredentialResponse. This function runs on the server and
   receives the output pub from the user running usrSession(),
   furthermore the server needs to load the user record created when
   registering the user with opaque_init_srv() or
   opaque_private_init_srv_finish(). These input parameters are
   transformed into a secret/shared session key sk and a response resp
   to be sent back to the user.
   @param [in] pub - the pub output of the opaque_session_user_start()
   @param [in] rec - the recorded created during "registration" and stored by the server
   @param [in] ids - the id if the client and server
   @param [in] infos - various extra (unspecified) protocol information as recommended by the rfc.
   @param [out] resp - servers response to be sent to the client where
   it is used as input into opaque_session_usr_finish()
   @param [out] sk - the shared secret established between the user & server
   @param [out] _ctx - the current context necessary for the explicit
   authentication of the user in opaque_session_server_auth(). This
   param is optional if no explicit user auth is necessary it can be
   set to NULL
   @return the function returns 0 if everything is correct
 */

int opaque_session_srv(const uint8_t pub[OPAQUE_USER_SESSION_PUBLIC_LEN], const uint8_t rec[OPAQUE_USER_RECORD_LEN], const Opaque_Ids *ids, const Opaque_App_Infos *infos, uint8_t resp[OPAQUE_SERVER_SESSION_LEN], uint8_t sk[crypto_secretbox_KEYBYTES], uint8_t _ctx[OPAQUE_SERVER_AUTH_CTX_LEN]);

/**
   This is the same function as defined in the paper with the
   usrSessionEnd name or RecoverCredentials as per the rfc. It is run by
   the user and receives as input the response from the previous server
   opaque_session_srv() function as well as the sec value from running
   the opaque_session_usr_start() function that initiated this
   instantiation of this protocol, All these input parameters are
   transformed into a shared/secret session key pk, which should be the
   same as the one calculated by the opaque_session_srv() function.

   @param [in] resp - the response sent from the server running opaque_session_srv()
   @param [in] sec - the private sec output of the client initiating
   this instantiation of this protocol using opaque_session_usr_start()
   @param [in] key - an value to be used as key during the final hashing
   of the OPRF, the rfc specifies this as 'RFCXXXX' but can be any other
   local secret amending the password typed in in the first step.
   @param [in] key_len - the length of the previous param key
   @param [in] cfg - the configuration of the envelope secret and cleartext part
   @param [in] infos - various extra (unspecified) protocol information
   as recommended by the rfc
   @param [out] ids - if ids were packed in the envelope - as given by
   the cfg param -, they are returned in this struct
   @param [out] sk - the shared secret established between the user & server
   @param [out] auth - the authentication code to be sent to the server
   in case explicit user authentication is required
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope
   @return the function returns 0 if the protocol is executed correctly
*/
int opaque_session_usr_finish(const uint8_t resp[OPAQUE_SERVER_SESSION_LEN], const uint8_t sec[OPAQUE_USER_SESSION_SECRET_LEN], const uint8_t *key, const uint64_t key_len, const Opaque_PkgConfig *cfg, const Opaque_App_Infos *infos, Opaque_Ids *ids, uint8_t *sk, uint8_t auth[crypto_auth_hmacsha256_BYTES], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   Explicit User Authentication.

   This is a function not explicitly in the original paper. In the
   ietf cfrg draft authentication is done using a hmac of the session
   transcript with different keys coming out of a hkdf after the key
   exchange.
   @param [in] ctx - the context returned by opaque_session_srv()
   @param [in] authU is the authentication token sent by the user.
   @param [in] infos is a pointer to a struct containing the
   info* /einfo* values used during the protocol instantiation (only
   info3/einfo3 is needed - the rest is already cached in ctx)
   @return the function returns 0 if the hmac verifies correctly.
 */
int opaque_session_server_auth(uint8_t _ctx[OPAQUE_SERVER_AUTH_CTX_LEN], const uint8_t authU[crypto_auth_hmacsha256_BYTES], const Opaque_App_Infos *infos);

/**
   Alternative user initialization

   The paper originally proposes a very simple 1 shot interface for
   registering a new "user", however this has the drawback that in
   that case the users secrets and its password are exposed in
   cleartext at registration to the server. There is an alternative 4
   message registration protocol specified by the rfc, which avoids
   the exposure of the secrets and the password to the server which
   can be instantiated by following for registration functions.
 */


/**
   Initial step to start registering a new user/client with the server.
   This function is called CreateRegistrationRequest in the rfc.
   The user inputs its password pw, and receives a secret context ctx
   and a blinded value alpha as output. ctx should be protected until
   step 3 of this registration protocol and the value alpha should be
   passed to the server.
   @param [in] pw - the users password
   @param [in] pwlen - length of the users password
   @param [out] ctx - a secret context needed for the 3rd step in this
   registration protocol - this needs to be protected and sanitized
   after usage.
   @param [out] alpha - the blinded hashed password as per the OPRF,
   this needs to be sent to the server together with any other
   important and implementation specific info such as user/client id,
   envelope configuration etc.
   @return the function returns 0 if everything is correct.
 */
int opaque_private_init_usr_start(const uint8_t *pw, const size_t pwlen, uint8_t ctx[OPAQUE_REGISTER_USER_SEC_LEN+pwlen], uint8_t *alpha);

/**
   Server evaluates OPRF and creates a user-specific public/private keypair

   This function is called CreateRegistrationResponse in the rfc.
   The server receives alpha from the users invocation of its
   opaque_private_init_usr_start() function, it outputs a value sec
   which needs to be protected until step 4 by the server. This
   function also outputs a value pub which needs to be passed to the
   user.
   @param [in] alpha - the blinded password as per the OPRF.
   @param [out] sec - the private key and the OPRF secret of the server.
   @param [out] pub - the evaluated OPRF and pubkey of the server to
   be passed to the client into opaque_private_init_usr_respond()
   @return the function returns 0 if everything is correct.
 */
int opaque_private_init_srv_respond(const uint8_t *alpha, uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   2nd step of registration: Server evaluates OPRF - Global Server Key Version

   This function is essentially the same as
   opaque_private_init_srv_respond(), except it does not generate a
   per-user long-term key, but instead expects the servers long-term
   pubkey as a parameter.

   This function is called CreateRegistrationResponse in the rfc.
   The server receives alpha from the users invocation of its
   opaque_private_init_usr_start() function, it outputs a value sec
   which needs to be protected until step 4 by the server. This
   function also outputs a value pub which needs to be passed to the
   user.
   @param [in] alpha - the blinded password as per the OPRF.
   @param [in] pk - the servers long-term pubkey
   @param [out] sec - the private key and the OPRF secret of the server.
   @param [out] pub - the evaluated OPRF and pubkey of the server to
   be passed to the client into opaque_private_init_usr_respond()
   @return the function returns 0 if everything is correct.
 */
int opaque_private_init_1ksrv_respond(const uint8_t *alpha, const uint8_t pk[crypto_scalarmult_BYTES], uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t _pub[OPAQUE_REGISTER_PUBLIC_LEN]);

/**
   Client finalizes registration by concluding the OPRF, generating
   its own keys and enveloping it all.

   This function is called FinalizeRequest in the rfc.  This function
   is run by the user, taking as input the context ctx that was an
   output of the user running opaque_private_init_usr_start(), and the
   output pub from the server of opaque_private_init_srv_respond().
   The key parameter can be used as an extra contribution to the
   derivation of the rwd by means of being used as a key to the final
   hash, if not specified it uses the value specified by the rfc. The
   result of this is the value rec which should be passed for the last
   step to the server.

   @param [in] ctx - output from opaque_private_init_usr_start(),
   should be sanitized after usage.
   @param [in] pub - response from the server running
   opaque_private_init_srv_respond()
   @param [in] key - an value to be used as key during the final hashing
   of the OPRF, the rfc specifies this as 'RFCXXXX' but can be any other
   local secret amending the password typed in in the first step.
   @param [in] key_len - the length of the previous param key
   @param [in] cfg - the configuration of the envelope secret and cleartext part
   @param [in] ids - if ids are to be packed in the envelope - as given by
   the cfg param
   @param [out] rec - the opaque record to be stored at the server
   this is a pointer to memory allocated by the caller, and must be
   large enough to hold the record and take into account the variable
   length of idU and idS in case these are included in the envelope.
   @param [out] export_key - key used to encrypt/authenticate extra
   material not stored directly in the envelope

   @return the function returns 0 if everything is correct.
 */
int opaque_private_init_usr_respond(const uint8_t *ctx, const uint8_t pub[OPAQUE_REGISTER_PUBLIC_LEN], const uint8_t *key, const uint64_t key_len, const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, uint8_t rec[OPAQUE_USER_RECORD_LEN], uint8_t export_key[crypto_hash_sha256_BYTES]);

/**
   Final Registration step - server adds own info to the record to be stored.

   The rfc does not explicitly specify this function.
   The server combines the sec value from its run of its
   opaque_private_init_srv_respond() function with the rec output of
   the users opaque_private_init_usr_respond() function, creating the
   final record, which should be the same as the output of the 1-step
   storePwdFile() init function of the paper. The server should save
   this record in combination with a user id and/or sid value as
   suggested in the paper.

   @param [in] sec - the private value of the server running
   opaque_private_init_srv_respond() in step 2 of the registration
   protocol
   @param [in/out] rec - input the record from the client running
   opaque_private_init_usr_respond() - output the final record to be
   stored by the server this is a pointer to memory allocated by the
   caller, and must be large enough to hold the record and take into
   account the variable length of idU and idS in case these are
   included in the envelope.
 */
void opaque_private_init_srv_finish(const uint8_t sec[OPAQUE_REGISTER_SECRET_LEN], uint8_t rec[OPAQUE_USER_RECORD_LEN]);

/**
   Final Registration step Global Server Key Version - server adds own info to the record to be stored.

   this function essentially does the same as
   opaque_private_init_srv_finish() except that it needs the global
   serve secret key as a parameter.

   The rfc does not explicitly specify this function.
   The server combines the sec value from its run of its
   opaque_private_init_srv_respond() function with the rec output of
   the users opaque_private_init_usr_respond() function, creating the
   final record, which should be the same as the output of the 1-step
   storePwdFile() init function of the paper. The server should save
   this record in combination with a user id and/or sid value as
   suggested in the paper.

   @param [in] sec - the private value of the server running
   opaque_private_init_srv_respond() in step 2 of the registration
   protocol
   @param [in] sk - the servers long-term private key
   @param [in/out] rec - input the record from the client running
   opaque_private_init_usr_respond() - output the final record to be
   stored by the server this is a pointer to memory allocated by the
   caller, and must be large enough to hold the record and take into
   account the variable length of idU and idS in case these are
   included in the envelope.
 */
void opaque_private_init_1ksrv_finish(const uint8_t _sec[OPAQUE_REGISTER_SECRET_LEN], const uint8_t sk[crypto_scalarmult_SCALARBYTES], uint8_t _rec[OPAQUE_USER_RECORD_LEN]);

/**
   helper function calculating the length of the two parts of the envelope

   based on the config and the length of the id[U|S] returns the size
   for the SecEnv or the ClrEnv portion of the envelope

   @param [in] cfg - the configuration of the envelope secret and cleartext part
   @param [in] ids - if ids are to be packed in the envelope - as given by
   the cfg param
   @param [in] type - InSecEnv|InClrEnv - calling with NotPackaged is useless

   @return the function returns the size of the envelope part specified in the param type.
 */
size_t package_len(const Opaque_PkgConfig *cfg, const Opaque_Ids *ids, const Opaque_PkgTarget type);

#endif // opaque_h
