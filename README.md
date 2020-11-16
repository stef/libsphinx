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
bind to this library.

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

## Standalone Binaries

libsphinx comes with very simple binaries implementing the sphinx
protocol, so you can build your own password storage even from shell
scripts.  Each step in the SPHINX protocol is handled by one binary:

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
