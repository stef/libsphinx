libdecaf (goldilocks) based sphinx implementation

sphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

sphinx has a very simple interface

## step 1 - challenge
the following creates a challenge for a device:
```
echo -n "shitty master password" | ../challenge >c 2>b
```
The master password is passed in through standard input.

The challenge is sent to standard output.

A blinding factor is stored in a tempfile, the name of this file is output to
stderr. This tempfile is needed in the last step again.

## step 2 - device responds
Pass the challenge from step 1 on standard input like:
```
../respond secret <c >r0
```
The response is sent to standard output.

## step 3 - derive password
To derive a (currently hex) password, pass the response from step 2 on standard
input and the filename of the tempfile from step 1 like:
```
fname=$(cat b)
../derive $fname <r0 >pwd0
```
The derived password is sent to standard output and currently is a 32 byte
binary string. Further transformations can be added which make it satisfy
various character set requirements, this is todo ;)
