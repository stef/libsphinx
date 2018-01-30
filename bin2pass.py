#!/usr/bin/env python

import sys, struct, math

sets = {
    # symbols
    's': tuple(chr(x) for x in range(32,48)+range(58,65)+range(91,97)+range(123,127)),
    # digits
    'd': tuple(chr(x) for x in range(48,58)),
    # upper-case
    'u': tuple(chr(x) for x in range(65,91)),
    # lower-case
    'l': tuple(chr(x) for x in range(97,123))}

def encode(raw, chars):
    l = len(raw)
    r = l % 4
    if r:
        raw += '\0' * (4 - r)
    longs = len(raw) >> 2
    out = []
    words = struct.unpack('>%dL' % (longs), raw)

    char_size = len(chars)
    out_fact=int(math.log(2**32, char_size))+1
    for word in words:
        for _ in xrange(out_fact):
            word, r = divmod(word, char_size)
            out += chars[r]

    out = ''.join(out)

    # Trim padding
    olen = l % 4
    if olen:
        olen += 1
    olen += l / 4 * out_fact
    return out[:olen]

def usage():
    print "usage: %s [d|u|s|l] [<max size>] <binary\tgenerate password with [d]igits/[u]pper/[l]ower/[s]ymbols of <max size> {default: duls}" % sys.argv[0]
    sys.exit(0)

if len(sys.argv)>3 or sys.argv in ('-h', '--help'):
    usage()

size = 0

raw = sys.stdin.read(32)

if len(sys.argv)==1:
    chars = sets['s']+sets['d']+sets['u']+sets['l']

elif len(sys.argv)==2: # figure out if set or size
    try:
        size = int(sys.argv[1])
    except ValueError:
        # probably a set specification
        chars = tuple(c for x in (sets[c] for c in ('s','u','l','d') if c in sys.argv[1]) for c in x)
else:
    try:
        size = int(sys.argv[2])
    except ValueError:
        usage();
    chars = tuple(c for x in (sets[c] for c in ('s','u','l','d') if c in sys.argv[1]) for c in x)

if size<0:
    print "error size must be < 0"
    usage()

password = encode(raw,chars)
if size>0: password=password[:size]
print password
