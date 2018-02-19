libdecaf-based sphinx password storage implementation

sphinx: a password *S*tore that *P*erfectly *H*ides from *I*tself
(*N*o *X*aggeration)

pitchforked sphinx is a cryptographic password storage as described in
https://eprint.iacr.org/2015/1099

## Dependencies

You need [libsphinx](https://github.com/stef/pitchforkedsphinx).

You need also to install `pysodium` using either your OS package
manager or pip.

## Installation

`pip install pwdsphinx` should get you started.


## API

`sphinxlib` is a `ctypes`-based python wrapper around libsphinx, so
you can build whatever you fancy immediately in python. The interface
exposed wraps the 3 sphinx functions from the library like this:

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

The functions for the PAKE (OPAQUE) protocol are not yet exposed.

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

### sphinx - the client

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
echo 'my master password' | ./sphinx.py create username https://example.com ulsd 0
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
echo 'my master password' | ./sphinx.py get username https://example.com
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
echo 'my master password' | ./sphinx.py change username https://example.com
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
./sphinx.py delete username https://example.com
```

You provide the `delete` operation as the first parameter to the
client, your `username` as the 2nd and the `site` as the 3rd
parameter. This command does not need anything on standard input, nor
does it provide anything on standard output in case everything goes
well.
