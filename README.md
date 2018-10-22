sphinx: a password **S**tore that **P**erfectly **H**ides from **I**tself
(**N**o **X**aggeration)

libsphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

and as presented by the Levchin Prize winner 2018 Hugo Krawczyk on
Real World Crypto https://www.youtube.com/watch?v=px8hiyf81iM

it also implements:

  - the PKI-free PAKE protocol as specified on page 18 of the same publication
  - The OPAQUE protocol as specified on page 28 of: https://eprint.iacr.org/2018/163 - see also OPAQUE.md

## What is this thing?

It allows you to have only a few (at least one) passwords that you
need to remember, while at the same time provides unique 40 (ASCII)
character long very random passwords (256 bit entropy). Your master
password is encrypted (blinded) and sent to the password storage
server which (without decrypting) combines your encrypted password
with a big random number and sends this (still encrypted) back to you,
where you can decrypt it (it's a kind of end-to-end encryption of
passwords) and use the resulting unique, strong and very random
password to register/login to various services. The resulting strong
passwords make offline password cracking attempts infeasible. If say
you use this with google and their password database is leaked your
password will still be safe.

How is this different from my password storage which stores the
passwords in an encrypted database? Most importantly using an
encrypted database is not "end-to-end" encrypted. Your master password
is used to decrypt the database read out the password and send it back
to you. This means whoever has your database can try to crack your
master password on it, or can capture your master password while you
type or send it over the network. Then all your passwords are
compromised. If some attacker compromises your traditional password
store it's mostly game over for you. Using sphinx the attacker
controlling your password store learns nothing about your master nor
your individual passwords. Also even if your strong password leaks,
it's unique and cannot be used to login to other sites or services.

## Installing

Install `python`, `libsodium`  and `libsodium-dev` using your operating system provided
package management. 

Building everything should (hopefully) be quite simple afterwards:

```
git submodule update --init --recursive --remote
cd src
make
```

## Library

libsphinx builds a library, which you can use to build your
own password manager either in C/C++ or any other language that can
bind to this library. The library also contains an experimental
version of the PKI-free PAKE protocol from page 18 of the paper.

### The Sphinx API
The Library exposes the following 3 functions for the FK-PTR protocol
(the password storage):

```
void sphinx_challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal);
```
 * pwd, p_len: are input params, containing the master password and its length
 * bfac: is an output param, it's a pointer to an array of
   `SPHINX_255_SCALAR_BYTES` (32) bytes - the blinding factor
 * chal: is an output param, it's a pointer to an array of
   `SPHINX_255_SER_BYTES` (32) bytes - the challenge

```
int sphinx_respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp);
```
 * chal: is an input param, it is the challenge from the challenge()
   function, it has to be a `SPHINX_255_SER_BYTES` (32) bytes big array
 * secret: is an input param, it is the "secret" contribution from the
   device, it is a `SPHINX_255_SCALAR_BYTES` (32) bytes long array
 * resp: is an output parameter, it is the result of this step, it
   must be a `SPHINX_255_SER_BYTES` (32) byte sized array
 * the function returns 1 on error, 0 on success

```
int sphinx_finish(const uint8_t *pwd, const size_t p_len,
                  const uint8_t *bfac, const uint8_t *resp,
                  uint8_t *rwd);
```

 * pwd: is an input param, it specifies the password again.
 * p_len: is an input param, it specifies the password length
 * bfac: is an input param, it is the bfac output from challenge(),
   it is array of `SPHINX_255_SCALAR_BYTES` (32) bytes
 * resp: is an input parameter, it's the response from respond(), it
   is a `SPHINX_255_SER_BYTES` (32) byte sized array
 * rwd: is an output param, the derived (binary) password, it is a
   `SPHINX_255_SER_BYTES` (32) byte array
 * this function returns 1 on error, 0 on success

### The PKI-free PAKE API

The following functions implement the PKI-free PAKE protocol, (for the
explanation of the various parameters please see the original paper
and the `src/tests/pake-test.c` example file):

```
void pake_server_init(uint8_t *p_s, uint8_t *P_s);
```

This function is called when setting up a new server. It creates a
long-term identity keypair. The public key needs to be shared with all
clients, the secret key needs to be well protected and persisted for
later usage.

```
void pake_client_init(const uint8_t *rwd, const size_t rwd_len,
                      const uint8_t *P_s,
                      uint8_t k_s[32], uint8_t c[32],
                      uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]);
```

This function needs to be run on the client when registering at a
server. The output parameters need to be sent to the server.


```
void pake_start_pake(const uint8_t *rwd, const size_t rwd_len,
                     uint8_t alpha[32], uint8_t x_u[32],
                     uint8_t X_u[32], uint8_t sp[32]);
```

The client initiates a "login" to the server with this function.

```
int pake_server_pake(const uint8_t alpha[32], const uint8_t X_u[32],  // input params
                     const uint8_t k_s[32], const uint8_t P_u[32],
                     const uint8_t p_s[32],
                     uint8_t beta[32], uint8_t X_s[32],               // output params
                     uint8_t SK[DECAF_X25519_PUBLIC_BYTES]);
```

This function implements the "login" on the server, it reuses the data
received when registering the user, and some other parameters that
came out of start_pake() when the client initiated the "login". At
successful completion SK should be a shared secret with the client. On
error the function return 1, otherwise 0.

```
int pake_user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t sp[32],
                   const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32],
                   const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32],
                   const uint8_t P_s[32], const uint8_t X_s[32],
                   uint8_t SK[DECAF_X25519_PUBLIC_BYTES]);
```

This function finalizes the "login" on the client side. At successful
completion SK should be a shared secret with the server. On error the
function return 1, otherwise 0.

### OPAQUE API

The following functions implement the OPAQUE protocol with the following deviations:

 0. does not implement any persistence/lookup functionality.
 1. instead of HMQV (which is patented) it implements a Triple-DH instead.
 2. it implements "user iterated hashing" from page 29 of the paper
 3. additionally implements a variant where U secrets never hit S unprotected

For more information please see the original paper and the
`src/tests/opaque-test.c` example file.

```
int storePwdFile(const uint8_t *pw, Opaque_UserRecord *rec);
```

This function implements the same function from the paper. This
function runs on the server and creates a new output record `rec` of
secret key material partly encrypted with a key derived from the input
password `pw`. The server needs to implement the storage of this
record and any binding to user names or as the paper suggests `sid`.

```
void usrSession(const uint8_t *pw, Opaque_UserSession_Secret *sec, Opaque_UserSession *pub);
```

This function initiates a new OPAQUE session, is the same as the
function defined in the paper with the same name. The User initiates a
new session by providing its input password `pw`, and receving a
private `sec` and a "public" `pub` output parameter. The User should
protect the `sec` value until later in the protocol and send the `pub`
value over to the Server, which process this with the following function:

```
int srvSession(const Opaque_UserSession *pub, const Opaque_UserRecord *rec, Opaque_ServerSession *resp, uint8_t *sk);
```

This is the same function as defined in the paper with the same
name. It runs on the server and receives the output `pub` from the
user running `usrSession()`, futhermore the server needs to load the
user record created when registering the user with the `storePwdFile()`
function. These input parameters are transformed into a secret/shared
session key `sk` and a response `resp` to be sent back to the user to
finish the protocol with the following `userSessionEnd()` function:

```
int userSessionEnd(const Opaque_ServerSession *resp, const Opaque_UserSession_Secret *sec, const uint8_t *pw, uint8_t *pk);
```

This is the same function as defined in the paper with the same
name. It is run by the user, and recieves as input the response from
the previous server `srvSession()` function as well as the `sec` value
from running the `usrSession()` function that initiated this protocol,
the user password `pw` is also needed as an input to this final
step. All these input parameters are transformed into a shared/secret
session key `pk`, which should be the same as the one calculated by
the `srvSession()` function.

#### Alternative registration API

The paper original proposes a very simple 1 shot interface for
registering a new "user", however this has the drawback that in that
case the users secrets and its password are exposed in cleartext at
registration to the server. There is a much less efficient 4 message
registration protocol which avoids the exposure of the secrets and the
password to the server which can be instantiated by the following for
registration functions:

```
void newUser(const uint8_t *pw, uint8_t *r, uint8_t *alpha);
```

The user inputs its password `pw`, and receives an ephemeral secret
`r` and a blinded value `alpha` as output. `r` should be protected
until step 3 of this registration protocol and the value `alpha`
should be passed to the servers `initUser()` function:

```
int initUser(const uint8_t *alpha, Opaque_RegisterSec *sec, Opaque_RegisterPub *pub);
```

The server receives `alpha` from the users invocation of its
`newUser()` function, it outputs a value `sec` which needs to be
protected until step 4 by the server. This function also outputs a
value `pub` which needs to be passed to the user who will use it in
its `registerUser()` function:

```
int registerUser(const uint8_t *pw, const uint8_t *r, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);
```

This function is run by the user, taking as input the users password
`pw`, the ephemeral secret `r` that was an output of the user running
`newUser()`, and the output `pub` from the servers run of
`initUser()`. The result of this is the value `rec` which should be
passed for the last step to the servers `saveUser()` function:

```
void saveUser(const Opaque_RegisterSec *sec, const Opaque_RegisterPub *pub, Opaque_UserRecord *rec);
```

The server combines the `sec` value from its run of its `initUser()`
function with the `rec` output of the users `registerUser()` function,
creating the final record, which should be the same as the output of
the 1-step `storePwdFile()` init function of the paper. The server
should save this record in combination with a user id and/or `sid`
value as suggested in the paper.

```
void opaque_f(const uint8_t *k, const size_t k_len, const uint8_t val, uint8_t *res);
```

This is a simple utility function that can be used to calculate
`f_k(c)`, where `c` is a constant, this is useful if the peers want to
authenticate each other.

If the server wants to authenticate itself to the user it sends the
user the output `auth` of `opaque_f(sk,sizeof sk, 1, auth)`, where
`sk` is the output from `srvSession()`. The user then verifies if this
`auth` is the same as the result of `opaque_f(pk,sizeof pk, 1, auth2)`,
where `pk` is the result from `userSessionEnd()`.

For the other direction, user authenticating to the server, reverse
the operations and use the value 2 for `c` instead of 1:
`opaque_f(pk,sizeof pk, 2, auth)` ->  `opaque_f(sk,sizeof sk, 2, auth2)`
and make sure `auth==auth2`.

## Standalone Binaries

libsphinx comes with very simple binaries implementing the sphinx
protocol, so you can build your own password storage even from shell
scripts. There are no such binaries provided for the PKI-free PAKE nor
the OPAQUE protocols. Each step in the SPHINX protocol is handled by
one binary:

### step 1 - challenge
The following creates a challenge for a device:
```
echo -n "shitty master password" | ./challenge >c 2>b
```
The master password is passed in through standard input.

The challenge is sent to standard output.

A blinding factor is stored in a tempfile, the name of this file is output to
stderr. This tempfile is needed in the last step again.

### step 2 - device responds
Pass the challenge from step 1 on standard input like:
```
./respond secret <c >r0
```
The response is sent to standard output.

### step 3 - derive password
To derive a (currently hex) password, pass the response from step 2 on
standard input and the filename of the tempfile from step 1 like:

```
fname=$(cat b) ./derive $fname <r0 >pwd0
```

The derived password is sent to standard output and currently is a 32
byte binary string. Please note that currently this only outputs the
unblinded H(pwd)^k, for the full protocol this should be hashed again
with the password prepended.

### step 4 - transform into ASCII password

The output from step 3 is a 32 byte binary string, most passwords have some
limitations to accept only printable - ASCII - chars. `bin2pass.py` is a python
script in the [pwdsphinx](https://github.com/stef/pwdsphinx) python module which takes a binary input on standard
input and transforms it into an ASCII password. It can have max two parameters
the classes of characters allowed ([**u**]pper-, [**l**]ower-case letters,
[**d**]igits and [**s**]ymbols) and the size of the password. The following
examples should make this clear:

Full ASCII, max size:
```
./bin2pass.py <pwd0
```
no symbols, max size:
```
./bin2pass.py uld <pwd0
```
no symbols, 8 chars:
```
./bin2pass.py uld 8 <pwd0
```
only digits, 4 chars:
```
./bin2pass.py d 4 <pwd0
```
only letters, 16 chars:
```
./bin2pass.py ul 16 <pwd0
```
