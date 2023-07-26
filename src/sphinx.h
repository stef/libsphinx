#ifndef sphinx_h
#define sphinx_h
/*
    @copyright 2018-2021, sphinx@ctrlc.hu
    This file is part of libsphinx.

    SPDX-FileCopyrightText: 2018-21, Marsiske Stefan
    SPDX-License-Identifier: GPL-3.0-or-later

    libsphinx is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libsphinx is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libsphinx. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#define SPHINX_255_SCALAR_BYTES crypto_core_ristretto255_SCALARBYTES
#define SPHINX_255_SER_BYTES crypto_core_ristretto255_BYTES

int sphinx_challenge(const uint8_t *pwd, const size_t p_len,
                     const uint8_t *salt,
                     const size_t salt_len,
                     uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
                     uint8_t chal[crypto_core_ristretto255_BYTES]);
int sphinx_respond(const uint8_t chal[crypto_core_ristretto255_BYTES],
                   const uint8_t secret[crypto_core_ristretto255_SCALARBYTES],
                   uint8_t resp[crypto_core_ristretto255_BYTES]);
int sphinx_finish(const uint8_t *pwd, const size_t p_len,
                  const uint8_t bfac[crypto_core_ristretto255_SCALARBYTES],
                  const uint8_t chal[crypto_core_ristretto255_BYTES],
                  const uint8_t resp[crypto_core_ristretto255_BYTES],
                  const uint8_t salt[crypto_pwhash_SALTBYTES],
                  uint8_t rwd[crypto_core_ristretto255_BYTES]);

#endif // sphinx_h
