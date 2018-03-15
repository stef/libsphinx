sphinx: a password **S**tore that **P**erfectly **H**ides from **I**tself
(**N**o **X**aggeration)

libsphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

and as presented by the Levchin Prize winner 2018 Hugo Krawczyk on
Real World Crypto https://www.youtube.com/watch?v=px8hiyf81iM

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

Install `libsodium`  and `libsodium-dev` using your operating system provided
package management. 

Building everything should (hopefully) be quite simple afterwards:

```
git submodule init
git submodule update --recursive --remote
cd src
make
```

## Library

libsphinx builds a library, which you can use to build your
own password manager either in C/C++ or any other language that can
bind to this library. The library also contains an experimental
version of the PKI-free PAKE protocol from page 18 of the paper.

The Library exposes the following 3 functions for the FK-PTR protocol
(the password storage):

```
void challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal);
```
 * pwd, p_len: are input params, containing the master password and its length
 * bfac: is an output param, it's a pointer to an array of
   `DECAF_255_SCALAR_BYTES` (32) bytes - the blinding factor
 * chal: is an output param, it's a pointer to an array of
   `DECAF_255_SER_BYTES` (32) bytes - the challenge

```
int respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp);
```
 * chal: is an input param, it is the challenge from the challenge()
   function, it has to be a `DECAF_255_SER_BYTES` (32) bytes big array
 * secret: is an input param, it is the "secret" contribution from the
   device, it is a `DECAF_255_SCALAR_BYTES` (32) bytes long array
 * resp: is an output parameter, it is the result of this step, it
   must be a `DECAF_255_SER_BYTES` (32) byte sized array
 * the function returns 1 on error, 0 on success

```
int finish(const uint8_t *bfac, const uint8_t *resp, uint8_t *rwd);
```

 * bfac: is an input param, it is the bfac output from challenge(),
   it is array of `DECAF_255_SCALAR_BYTES` (32) bytes
 * resp: is an input parameter, it's the response from respond(), it
   is a `DECAF_255_SER_BYTES` (32) byte sized array
 * rwd: is an output param, the derived (binary) password, it is a
   `DECAF_255_SER_BYTES` (32) byte array
 * this function returns 1 on error, 0 on success

The following functions implement the PKI-free PAKE protocol, (for the
explanation of the various parameters please see the original paper
and the pake-test.c example file):

```
void server_init(uint8_t *p_s, uint8_t *P_s);
```

This function is called when setting up a new server. It creates a
long-term identity keypair. The public key needs to be shared with all
clients, the secret key needs to be well protected and persisted for
later usage.

```
void client_init(const uint8_t *rwd, const size_t rwd_len,
                 const uint8_t *P_s,
                 uint8_t k_s[32], uint8_t c[32],
                 uint8_t C[32], uint8_t P_u[32], uint8_t m_u[32]);
```

This function needs to be run on the client when registering at a
server. The output parameters need to be sent to the server.


```
void start_pake(const uint8_t *rwd, const size_t rwd_len,
                uint8_t alpha[32], uint8_t x_u[32],
                uint8_t X_u[32], uint8_t sp[32]);
```

The client initiates a "login" to the server with this function.

```
int server_pake(const uint8_t alpha[32], const uint8_t X_u[32],  // input params
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
int user_pake(const uint8_t *rwd, const size_t rwd_len, const uint8_t sp[32],
              const uint8_t x_u[32], const uint8_t beta[32], const uint8_t c[32],
              const uint8_t C[32], const uint8_t P_u[32], const uint8_t m_u[32],
              const uint8_t P_s[32], const uint8_t X_s[32],
              uint8_t SK[DECAF_X25519_PUBLIC_BYTES]);
```

This function finalizes the "login" on the client side. At successful
completion SK should be a shared secret with the server. On error the
function return 1, otherwise 0.

## Standalone Binaries

libsphinx comes with very simple binaries, so you can build
your own password storage even from shell scripts. Each step in the
protocol is handled by one binary:

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
To derive a (currently hex) password, pass the response from step 2 on standard
input and the filename of the tempfile from step 1 like:
```
fname=$(cat b)
./derive $fname <r0 >pwd0
```
The derived password is sent to standard output and currently is a 32 byte
binary string.

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
