libdecaf-based sphinx password storage implementation

sphinx: a password *S*tore that *P*erfectly *H*ides from *I*tself
(*N*o *X*aggeration)

pitchforked sphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

and as presented by the Levchin Prize winner 2018 Hugo Krawczyk on
Real World Crypto https://www.youtube.com/watch?v=px8hiyf81iM

pitchforked sphinx comes with variety of interfaces: a library, a
python wrapper around that library, a network server/client written in
python and simple command-line binaries.

## What is this thing?

It allows you to have only a few (at least one) passwords that you
need to remember, while at the same time provides unique 40 character
long very random passwords (256 bit entropy). Your master password is
encrypted (blinded) and sent to the password storage server which
(without decrypting) combines your encrypted password with a big
random number and sends this (still encrypted) back to you, where you
can decrypt it (it's a kind of end-to-end encryption of passwords) and
use the resulting unique, strong and very random password to
register/login to various services. The resulting strong passwords
make offline password cracking attempts infeasible. If say you use
this with google and their password database is leaked your password
will still be safe.

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

Install libsodium using your operating system provided package
management. And if you use any of the python goodies you need to
install also pysodium using either your OS package manager or pip.

Building everything should be quite simple afterwards:

```
git submodule init
make
```

## Library

Pitchforked sphinx builds a library, which you can use to build your
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

## Python wrapper

Pitchforked sphinx also comes with a python wrapper, so you can build
whatever you fancy immediately in python. The interface exposed wraps
the 3 sphinx functions from the library like this:

```
def challenge(pwd)
```

returns bfac and chal

```
def respond(chal, secret)
```
return the response


```
def finish(bfac, resp)
```

returns the raw 32 byte password.

The functions for the PAKE protocol are not yet exposed.

## Server/Client

Since the sphinx protocol only makes sense if the "device" is
somewhere else than where you type your password, pitchforked sphinx
comes with a server implemented in py3 which you can host off-site
from your usual desktop/smartphone. Also a client is supplied which is
able to communicate with the server and manage passwords.

### oracle - the server

The server can be "configured" by changing the variables on top of the file.

The address is the IP address on which the server is listening,
default is `localhost` - you might want to change that. The port is
by default 2355. And a data directory where all the device "secrets"
are stored, this defaults to "data/" in the current directory. You
might want to back up this directory from time to time to an encrypted
medium.

Change these three variables to fit your needs. Starting the server
can be done simply by:

```
./oracle.py
```

### sphinx-client

This is the client that connects to the oracle to manage passwords
using the sphinx protocol.

#### Client Configuration

Like the server, the client can also be "configured" by setting the
variables at the top of the python script. The host and port should
match what you set in the server.

The datadir (default: `~/.sphinx`) variable holds the location for
your client parameters. Particularly it contains a salt (by default
`~/.sphinx/salt`) which is used to calculate the ids for secrets on
the server, and more importantly it also contains a secret key
(default: `~/.sphinx/key`) that is used to sign every message sent to
the server to authorize the operations on your passwords. Both the
salt and the key is generated automatically if not available. You
might want to back up and encrypt both the salt and the key.

#### Authorization

All operations are authenticated by your (default: `~/.sphinx/key`)
file which is used to sign all operations. You should protect this
file, so that only you can operate on your passwords.

#### Operations

The client provides the following operations: Create, Get, Change,
Delete. Note there is no command to list "records", as the server does
not contain any textual information about what it stores. All
operations need a username and a site this password belongs to.

#### Create password

Creating a new password for a site is easy, pass your "master"
password on standard input to the client, and provide parameters like
in this example:

```
echo 'my master password | ./sphinx-client.py create username https://example.com ulsd 0
```

The parameters to the client are `create` for the operation, then
`username` for the username on the site `https://example.com` then a
combination of the letters `ulsd` and the `0` for the size of the
final password. The letters `ulsd` stand in order for the following
character classes: `u` upper-case letters, `l` lower-case letters, `s`
symbols and `d` for digits.

Note, you can actually use different "master" passwords for different
user/site combinations.

#### Get password

Getting a password from the sphinx oracle works by running the
following command:

```
echo 'my master password | ./sphinx-client.py get username https://example.com
```

Here again you supply your master password on standard input, provide
the `get` operation as the first parameter, your `username` as the 2nd
and the `site` as the 3rd parameter. The resulting password is
returned on standard output.

#### Change password

You might want to (be forced to regularly) change your password, this
is easy while you can keep your master password the unchanged (or you
can change it too, if you want). The command is this:

```
echo 'my master password' | ./sphinx-client.py change username https://example.com
```

Here again you supply your master password on standard input. This
master password can be the same, but can also be a new password if you
want to change also the master password. You provide the `change`
operation as the first parameter to the client, your `username` as the
2nd and the `site` as the 3rd parameter. Your new new password is
returned on standard output.

#### Deleting passwords

In case you want to delete a password, you can do using the following
command:

```
./sphinx-client.py delete username https://example.com
```

You provide the `delete` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter. This command does not need anything on standard input, nor
does it provide anything on standard output in case everything goes
well.

## Standalone Binaries

pitchforked sphinx comes with very simple binaries, so you can build
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
script which takes a binary input on standard input and transforms it into an
ASCII password. It can have max two parameters the classes of characters
allowed ([*u*]pper-, [*l*]ower-case letters, [*d*]igits and [*s*]ymbols) and
the size of the password. The following examples should make this clear:

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
