#!/usr/bin/env python3

import sys, os, asyncio, io, struct, binascii, platform
import pysodium

try:
  from pwdsphinx import bin2pass, sphinxlib
  from pwdsphinx.config import getcfg
except ImportError:
  import bin2pass, sphinxlib
  from config import getcfg

win=False
if platform.system() == 'Windows':
  win=True

cfg = getcfg('sphinx')

verbose = cfg['client'].getboolean('verbose')
address = cfg['client']['address']
port = cfg['client']['port']
datadir = cfg['client']['datadir']

CREATE=b'\x00'
GET=b'\x66'
COMMIT=b'\x99'
CHANGE=b'\xaa'
DELETE=b'\xff'

class SphinxClientProtocol(asyncio.Protocol):
  def __init__(self, message, loop,b,handler,cb):
    self.b = b
    self.message = message
    self.loop = loop
    self.handler = handler
    self.cb = cb

  def connection_made(self, transport):
    transport.write(self.message)
    if verbose: print('Data sent: {!r}'.format(self.message))

  def data_received(self, data):
    if verbose: print('Data received: {!r}'.format(repr(data).encode()))

    try:
      data = pysodium.crypto_sign_open(data, self.handler.getserverkey())
    except ValueError:
      raise ValueError('invalid signature.\nabort')

    if data == b'fail':
        raise ValueError('fail')

    if not self.b:
      self.cb()
      return

    rwd=sphinxlib.finish(self.b, data)

    rule = self.handler.getrule()
    if not rule:
        raise ValueError("no password rule defined for this password.")
    rule, size = rule
    self.cb(bin2pass.derive(rwd,rule,size).decode())

  def connection_lost(self, exc):
    if verbose:
        print('The server closed the connection')
        print('Stop the event loop')
    self.loop.stop()

class SphinxHandler():
  def __init__(self, datadir):
    self.datadir=datadir

  def getkey(self):
    datadir = os.path.expanduser(self.datadir)
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
        if not win: os.fchmod(fd.fileno(),0o600)
        fd.write(sk)
      return sk

  def getsalt(self):
    datadir = os.path.expanduser(self.datadir)
    try:
      fd = open(datadir+'salt', 'rb')
      salt = fd.read()
      fd.close()
      return salt
    except FileNotFoundError:
      if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
      salt = pysodium.randombytes(32)
      with open(datadir+'salt','wb') as fd:
        if not win: os.fchmod(fd.fileno(),0o600)
        fd.write(salt)
      return salt

  def saverules(self, id, rules, size, user):
    datadir = os.path.expanduser(self.datadir+'/rules/')
    if not os.path.exists(datadir):
        os.mkdir(datadir,0o700)
    # convert rule to bitfields
    rules = sum(1<<i for i, c in enumerate(('u','l','s','d')) if c in rules)
    # pack rule
    rule=(rules << 7) | (size & 0x7f)
    fname = datadir+binascii.hexlify(id).decode()
    if not os.path.exists(fname):
      with open(fname, 'wb') as fd:
          fd.write(struct.pack('>H', rule))
          fd.write(user)
    else:
      with open(fname, 'ab') as fd:
          fd.write(b"\n"+user)

  def getusers(self, id):
    datadir = os.path.expanduser(self.datadir+'/rules/')
    try:
      with open(datadir+binascii.hexlify(id).decode(), 'rb') as fd:
        # skip rules
        fd.seek(2)
        return [x.strip() for x in fd.readlines()]
    except FileNotFoundError:
        return None

  def deluser(self, id, user):
    datadir = os.path.expanduser(self.datadir+'/rules/')
    try:
      with open(datadir+binascii.hexlify(id).decode(), 'rb') as fd:
        # skip rules
        rules = fd.read(2)
        users=[x.strip() for x in fd.readlines() if x.strip() != user.encode()]
      if users != []:
        with open(datadir+binascii.hexlify(id).decode(), 'wb') as fd:
            # skip rules
            fd.write(rules)
            fd.write(b'\n'.join(users))
      else:
        os.unlink(datadir+binascii.hexlify(id).decode())
    except FileNotFoundError:
      return None

  def getrule(self):
    datadir = os.path.expanduser(self.datadir+'/rules/')
    try:
      with open(datadir+binascii.hexlify(self.hostid).decode(), 'rb') as fd:
          rule = struct.unpack(">H",fd.read(2))[0]
      size = (rule & 0x7f)
      rule = {c for i,c in enumerate(('u','l','s','d')) if (rule >> 7) & (1 << i)}
      return (rule, size)
    except FileNotFoundError:
        return None

  def getserverkey(self):
    datadir = os.path.expanduser(self.datadir)
    try:
      with open(datadir+'server-key.pub', 'rb') as fd:
        key = fd.read()
      return key
    except FileNotFoundError:
      pass
    # try in installation dir
    BASEDIR = os.path.dirname(os.path.abspath(__file__))
    try:
      with open(BASEDIR+'/server-key.pub', 'rb') as fd:
        key = fd.read()
      return key
    except FileNotFoundError:
      print("no server key found, please install it")
      sys.exit(1)

  def getid(self, host, user):
    salt = self.getsalt()
    return pysodium.crypto_generichash(b''.join((user.encode(),host.encode())), salt, 32)

  def doSphinx(self, message, host, b, cb):
    self.hostid=pysodium.crypto_generichash(host, self.getsalt(), 32)
    signed=pysodium.crypto_sign(message,self.getkey())
    loop = asyncio.get_event_loop()
    coro = loop.create_connection(lambda: SphinxClientProtocol(signed, loop, b, self, cb), address, port)
    try:
      loop.run_until_complete(coro)
      loop.run_forever()
    except:
      raise

  def create(self, cb, pwd, user, host, char_classes, size=0):
    if set(char_classes) - {'u','l','s','d'}:
      raise ValueError("error: rules can only contain ulsd.")
    try: size=int(size)
    except:
      raise ValueError("error: size has to be integer.")
    if user.encode() in self.list(host):
      raise ValueError("error: User already exists.")

    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    self.saverules(hostid, char_classes, size, user.encode())

    b, c = sphinxlib.challenge(pwd)
    sk = self.getkey()
    message = b''.join([CREATE,
                        self.getid(host, user),
                        c,
                        pysodium.crypto_sign_sk_to_pk(sk)])
    self.doSphinx(message, host, b, cb)

  def get(self, cb, pwd, user, host):
    b, c = sphinxlib.challenge(pwd)
    message = b''.join([GET,
                        self.getid(host, user),
                        c])
    self.doSphinx(message, host, b, cb)

  def change(self, cb, pwd, user, host):
    b, c = sphinxlib.challenge(pwd)
    message = b''.join([CHANGE,
                        self.getid(host, user),
                        c])
    self.doSphinx(message, host, b, cb)

  def commit(self, cb, user, host):
    message = b''.join([COMMIT,self.getid(host, user)])
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    def callback():
      return
    self.doSphinx(message, host, None, callback)

  def delete(self, user, host):
    message = b''.join([DELETE,self.getid(host, user)])
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    def callback():
      self.deluser(hostid,user)
    self.doSphinx(message, host, None, callback)

  def list(self, host):
    salt = self.getsalt()
    hostid = pysodium.crypto_generichash(host, salt, 32)
    return self.getusers(hostid) or []

def main():
  def usage():
    print("usage: %s create <user> <site> [u][l][d][s] [<size>]" % sys.argv[0])
    print("usage: %s <get|change|commit|delete> <user> <site>" % sys.argv[0])
    print("usage: %s list <site>" % sys.argv[0])
    sys.exit(1)

  if len(sys.argv) < 2: usage()

  handler = SphinxHandler(datadir)

  if sys.argv[1] == 'create':
    if len(sys.argv) not in (5,6): usage()
    pwd = sys.stdin.buffer.read()
    if len(sys.argv) == 6:
      size=sys.argv[5]
    else:
      size = 0
    handler.create(print, pwd, sys.argv[2], sys.argv[3], sys.argv[4], size)
  elif sys.argv[1] == 'get':
    if len(sys.argv) != 4: usage()
    # needs id, challenge, sig(id)
    pwd = sys.stdin.buffer.read()
    handler.get(print, pwd, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'change':
    if len(sys.argv) != 4: usage()
    # needs id, challenge, sig(id)
    pwd = sys.stdin.buffer.read()
    handler.change(print, pwd, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'commit':
    if len(sys.argv) != 4: usage()
    handler.commit(print, sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'delete':
    if len(sys.argv) != 4: usage()
    handler.delete(sys.argv[2], sys.argv[3])
  elif sys.argv[1] == 'list':
    if len(sys.argv) != 3: usage()
    print(b'\n'.join(handler.list(sys.argv[2])).decode())
  else:
    usage()

if __name__ == '__main__':
  main()
