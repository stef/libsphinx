libdecaf-based sphinx password storage implementation

pitchforked sphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

pitchforked sphinx has a very simple interface

## step 1 - challenge
The following creates a challenge for a device:
```
echo -n "shitty master password" | ./challenge >c 2>b
```
The master password is passed in through standard input.

The challenge is sent to standard output.

A blinding factor is stored in a tempfile, the name of this file is output to
stderr. This tempfile is needed in the last step again.

## step 2 - device responds
Pass the challenge from step 1 on standard input like:
```
./respond secret <c >r0
```
The response is sent to standard output.

## step 3 - derive password
To derive a (currently hex) password, pass the response from step 2 on standard
input and the filename of the tempfile from step 1 like:
```
fname=$(cat b)
./derive $fname <r0 >pwd0
```
The derived password is sent to standard output and currently is a 32 byte
binary string.

## step 4 - transform into ASCII password
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
