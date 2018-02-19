"""Wrapper for libsphinx library

   Copyright (c) 2018, Marsiske Stefan.
   All rights reserved.

   This file is part of pitchforked sphinx.

   pitchforked sphinx is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of
   the License, or (at your option) any later version.

   pitchforked sphinx is distributed in the hope that it will be
   useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
   See the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with pitchforked sphinx. If not, see <http://www.gnu.org/licenses/>.
"""

import ctypes
import ctypes.util

sphinxlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sphinx') or ctypes.util.find_library('libsphinx'))

if not sphinxlib._name:
    raise ValueError('Unable to find libsphinx')

DECAF_255_SCALAR_BYTES = 32
DECAF_255_SER_BYTES    = 32

def __check(code):
    if code != 0:
        raise ValueError

# void challenge(const uint8_t *pwd, const size_t p_len, uint8_t *bfac, uint8_t *chal)
def challenge(pwd):
    if pwd == None:
        raise ValueError("invalid parameter")
    bfac = ctypes.create_string_buffer(DECAF_255_SCALAR_BYTES)
    chal = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    __check(sphinxlib.challenge(pwd, len(pwd), bfac, chal))
    return (bfac.raw, chal.raw)

# int respond(const uint8_t *chal, const uint8_t *secret, uint8_t *resp)
def respond(chal, secret):
    if None in (chal, secret):
        raise ValueError("invalid parameter")
    if len(chal) != DECAF_255_SER_BYTES: raise ValueError("truncated point")
    if len(secret) != DECAF_255_SCALAR_BYTES: raise ValueError("truncated secret")

    resp = ctypes.create_string_buffer(DECAF_255_SER_BYTES)

    __check(sphinxlib.respond(chal, secret, resp))
    return resp.raw

# int finish(const uint8_t *bfac, const uint8_t *resp, uint8_t *rwd)
def finish(bfac, resp):
    if None in (bfac, resp):
        raise ValueError("invalid parameter")
    if len(resp) != DECAF_255_SER_BYTES: raise ValueError("truncated point")
    if len(bfac) != DECAF_255_SCALAR_BYTES: raise ValueError("truncated secret")

    rwd = ctypes.create_string_buffer(DECAF_255_SER_BYTES)
    __check(sphinxlib.finish(bfac, resp, rwd))
    return rwd.raw
