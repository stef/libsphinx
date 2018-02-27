#!/usr/bin/env python3

import asyncio, datetime, os, binascii, shutil, sys
from SecureString import clearmem
import pysodium
from pwdsphinx import sphinxlib
from pwdsphinx.config import getcfg
cfg = getcfg('sphinx')

verbose = cfg['server'].getboolean('verbose')
address = cfg['server']['address']
port = cfg['server']['port']
datadir = cfg['server']['datadir']
keydir = cfg['server']['keydir']

if(verbose):
  cfg.write(sys.stdout)

CREATE=0x00
GET=0x66
COMMIT=0x99
CHANGE=0xaa
DELETE=0xff

def respond(chal, id):
  keyf = os.path.expanduser(datadir+binascii.hexlify(id).decode()+'/key')
  if not os.path.exists(keyf):
    print(keyf,'not exist')
    return b'fail' # key not found

  with open(keyf,'rb') as fd:
    secret = fd.read()

  if len(secret)!= sphinxlib.DECAF_255_SCALAR_BYTES:
    if verbose: print("secret wrong size")
    return b'fail'

  try:
    return sphinxlib.respond(chal, secret)
  except ValueError:
    if verbose: print("respond fail")
    return b'fail'

class SphinxOracleProtocol(asyncio.Protocol):
  def connection_made(self, transport):
    if verbose:
      peername = transport.get_extra_info('peername')
      print('{} Connection from {}'.format(datetime.datetime.now(), peername))
    self.transport = transport

  def create(self, data):
    # needs pubkey, id, challenge, sig(id)
    # returns output from ./response | fail
    pk = data[129:161]
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    if os.path.exists(tdir):
      print(tdir, 'exists')
      return b'fail' # key already exists

    os.mkdir(tdir,0o700)

    with open(tdir+'/pub','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(pk)

    k=pysodium.randombytes(32)
    with open(tdir+'/key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    return respond(chal, id)

  def getpk(self,data):
    id = data[65:97]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    with open(tdir+'/pub','rb') as fd:
      return fd.read()

  def get(self, data):
    # needs id, challenge, sig(id)
    # returns output from ./response | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]

    return respond(chal, id)

  def change(self, data):
    # needs id, challenge, sig(id)
    # returns output from ./response | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    chal = data[33:65]

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    k=pysodium.randombytes(32)
    with open(tdir+'/new','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    try:
      return sphinxlib.respond(chal, k)
    except ValueError:
      if verbose: print("respond fail")
      return b'fail'

  def commit(self, data):
    # needs id, sig(id)
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]
    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())

    try:
      with open(tdir+'/new','rb') as fd:
        k = fd.read()
    except FileNotFoundError:
      return b'fail'

    os.unlink(tdir+'/new')

    if(len(k)!=32):
      return b'fail'

    with open(tdir+'/key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(k)

    return b'ok'

  def delete(self, data):
    # needs id, sig(id)
    # returns ok | fail
    try:
      pk = self.getpk(data)
    except:
      return b'fail'
    try:
      data = pysodium.crypto_sign_open(data, pk)
    except ValueError:
      print('invalid signature')
      return b'fail'
    id = data[1:33]

    tdir = os.path.expanduser(datadir+binascii.hexlify(id).decode())
    shutil.rmtree(tdir)
    return b'ok'

  def data_received(self, data):
    res = b''

    if verbose:
      print('Data received: {!r}'.format(data))

    if data[64] == 0:
      res = self.create(data)
    elif data[64] == GET:
      # needs id, challenge, sig(id)
      # returns output from ./response | fail
      res = self.get(data)
    elif data[64] == CHANGE:
      # needs id, challenge, sig(id)
      # changes stored secret
      # returns output from ./response | fail
      res = self.change(data)
    elif data[64] == DELETE:
      # needs id, sig(id)
      # returns ok|fail
      res = self.delete(data)
    elif data[64] == COMMIT:
      # needs id, sig(id)
      # returns ok|fail
      res = self.commit(data)

    if verbose:
      print('Send: {!r}'.format(res))

    key = getkey(keydir)
    res=pysodium.crypto_sign(res,key)
    clearmem(key)
    self.transport.write(res)

    if verbose:
      print('Close the client socket')
    self.transport.close()

def getkey(keydir):
  datadir = os.path.expanduser(keydir)
  try:
    with open(datadir+'server-key', 'rb') as fd:
      key = fd.read()
    return key
  except FileNotFoundError:
    print("no server key found, generating...")
    if not os.path.exists(datadir):
      os.mkdir(datadir,0o700)
    pk, sk = pysodium.crypto_sign_keypair()
    with open(datadir+'server-key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(sk)
    with open(datadir+'server-key.pub','wb') as fd:
      fd.write(pk)
    print("please share `%s` with all clients"  % (datadir+'server-key.pub'))
    return sk

def main():
  loop = asyncio.get_event_loop()
  # Each client connection will create a new protocol instance
  coro = loop.create_server(SphinxOracleProtocol, address, port)
  server = loop.run_until_complete(coro)

  key = getkey(keydir)
  if key == None:
    print("no signing key available.\nabort")
    sys.exit(1)
  del key

  # Serve requests until Ctrl+C is pressed
  if verbose:
    print('Serving on {}'.format(server.sockets[0].getsockname()))
  try:
    loop.run_forever()
  except KeyboardInterrupt:
    pass

  # Close the server
  server.close()
  loop.run_until_complete(server.wait_closed())
  loop.close()

if __name__ == '__main__':
  main()
