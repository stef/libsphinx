#!/usr/bin/env python3

import sys, struct, math
from itertools import chain

sets = {
    # symbols
    's': tuple(bytes([x]) for x in chain(range(32,48),range(58,65),range(91,97),range(123,127))),
    # digits
    'd': tuple(bytes([x]) for x in range(48,58)),
    # upper-case
    'u': tuple(bytes([x]) for x in range(65,91)),
    # lower-case
    'l': tuple(bytes([x]) for x in range(97,123))}

def encode(raw, chars):
    l = len(raw)
    r = l % 4
    if r:
        raw += b'\0' * (4 - r)
    longs = len(raw) >> 2
    out = []
    words = struct.unpack('>%dL' % (longs), raw)

    char_size = len(chars)
    out_fact=int(math.log(2**32, char_size))+1
    for word in words:
        for _ in range(out_fact):
            word, r = divmod(word, char_size)
            out += chars[r]

    #out = b''.join(out)

    # Trim padding
    olen = l % 4
    if olen:
        olen += 1
    olen += l / 4 * out_fact
    return bytes(out[:int(olen)])

def derive(rwd,rule,size):
    chars = tuple(c for x in (sets[c] for c in ('s','u','l','d') if c in rule) for c in x)
    password = encode(rwd,chars)
    if size>0: password=password[:size]
    return password

def usage():
    print("usage: %s [d|u|s|l] [<max size>] <binary\tgenerate password with [d]igits/[u]pper/[l]ower/[s]ymbols of <max size> {default: duls}" % sys.argv[0])
    sys.exit(0)

def main():
  if len(sys.argv)>3 or sys.argv in ('-h', '--help'):
    usage()

  size = 0
  raw = sys.stdin.buffer.read(32)

  if len(sys.argv)==1:
    rule = 'ulsd'

  elif len(sys.argv)==2: # figure out if set or size
    try:
      size = int(sys.argv[1])
    except ValueError:
      # probably a set specification
      rule = sys.argv[1]
  else:
    try:
      size = int(sys.argv[2])
    except ValueError:
      usage();
    rule = sys.argv[1]

  if size<0:
    print("error size must be < 0")
    usage()

  print(derive(raw,rule,size))

if __name__ == '__main__':
  main()
