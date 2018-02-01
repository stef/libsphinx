#!/usr/bin/env python3

import pysodium, sys, os, asyncio, io, struct, binascii, sphinx
import bin2pass

verbose = False
addr = '127.0.0.1'
port = 2355
datadir = '~/.sphinx/'

CREATE=b'\x00'
GET=b'\x66'
CHANGE=b'\xaa'
DELETE=b'\xff'

class SphinxClientProtocol(asyncio.Protocol):
  def __init__(self, message, loop,b):
    self.b = b
    self.message = message
    self.loop = loop

  def connection_made(self, transport):
    transport.write(self.message)
    if verbose: print('Data sent: {!r}'.format(self.message))

  def data_received(self, data):
    if verbose: print('Data received: {!r}'.format(data.decode()))

    try:
      data = pysodium.crypto_sign_open(data, serverkey)
    except ValueError:
      print('invalid signature.\nabort')
      return

    if data == b'fail':
        print('fail')
        return

    if not self.b:
        return

    rwd=sphinx.finish(self.b, data)

    rule = getrule(datadir, id)
    if not rule:
        print("no password rule defined for this password.")
    rule, size = rule
    print(bin2pass.derive(rwd,rule,size).decode())

  def connection_lost(self, exc):
    if verbose:
        print('The server closed the connection')
        print('Stop the event loop')
    self.loop.stop()

def getkey(datadir):
  datadir = os.path.expanduser(datadir)
  try:
    fd = open(datadir+'key', 'rb')
    key = fd.read()
    fd.close()
    return key
  except FileNotFoundError:
    if not os.path.exists(datadir):
      os.mkdir(datadir,0o700)
    pk, sk = pysodium.crypto_sign_keypair()
    with open(datadir+'key','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(sk)
    return sk

def getsalt(datadir):
  datadir = os.path.expanduser(datadir)
  try:
    fd = open(datadir+'salt', 'rb')
    salt = fd.read()
    fd.close()
    return salt
  except FileNotFoundError:
    salt = pysodium.randombytes(32)
    with open(datadir+'salt','wb') as fd:
      os.fchmod(fd.fileno(),0o600)
      fd.write(salt)
    return salt

def saverules(datadir, id, rules, size):
  datadir = os.path.expanduser(datadir+'/rules/')
  if not os.path.exists(datadir):
      os.mkdir(datadir,0o700)
  # convert rule to bitfields
  rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in rules)
  # pack rule
  rule=(rules << 7) | (size & 0x7f)
  with open(datadir+binascii.hexlify(id).decode(), 'wb') as fd:
      fd.write(struct.pack('>H', rule))

def getrule(datadir, id):
  datadir = os.path.expanduser(datadir+'/rules/')
  try:
    fd = open(datadir+binascii.hexlify(id).decode(), 'rb')
    rule = struct.unpack(">H",fd.read(2))[0]
    size = (rule & 0x7f)
    rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
    return (rule, size)
  except FileNotFoundError:
      return None

def getserverkey(datadir):
  datadir = os.path.expanduser(datadir)
  try:
    with open(datadir+'server-key.pub', 'rb') as fd:
      key = fd.read()
    return key
  except FileNotFoundError:
    print("no server key found, please install it")
    sys.exit(1)

def usage():
  print("usage: %s <create> <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
  print("usage: %s <get|change|delete> <user> <site>" % sys.argv[0])
  sys.exit(1)

def challenge():
  pwd = sys.stdin.buffer.read()
  return sphinx.challenge(pwd)

if __name__ == '__main__':
  if ((len(sys.argv) > 1 and sys.argv[1]!='create' and len(sys.argv) != 4) or
      (len(sys.argv) > 1 and sys.argv[1]=='create' and len(sys.argv)!=6)):
      usage()

  sk = getkey(datadir)
  salt = getsalt(datadir)
  serverkey = getserverkey(datadir)
  id = pysodium.crypto_generichash(''.join((sys.argv[2],sys.argv[3])), salt, 32)
  b = None

  if sys.argv[1] == 'create':
    # needs pubkey, id, challenge, sig(id)
    # returns output from ./response | fail
    if set(sys.argv[4]) - {'u','l','s','d'}:
        print("error: rules can only contain ulsd.")
        usage()
    size = 0
    try: size=int(sys.argv[5])
    except:
        print("error: size has to be integer.")
        usage()
    saverules(datadir, id, sys.argv[4], size)
    b, c = challenge()
    message = [CREATE,id,c, pysodium.crypto_sign_sk_to_pk(sk)]
  elif sys.argv[1] == 'get':
    # needs id, challenge, sig(id)
    b, c = challenge()
    message = [GET,id,c]
    # returns output from ./response | fail
  elif sys.argv[1] == 'change':
    # needs id, challenge, sig(id)
    b, c = challenge()
    message = [CHANGE,id,c]
    # changes stored secret
    # returns output from ./response | fail
  elif sys.argv[1] == 'delete':
    # needs id, sig(id)
    message = [DELETE,id]
  else:
    usage()

  message=pysodium.crypto_sign(b''.join(message),sk)

  loop = asyncio.get_event_loop()
  coro = loop.create_connection(lambda: SphinxClientProtocol(message, loop, b), addr, port)
  loop.run_until_complete(coro)
  loop.run_forever()
  loop.close()
