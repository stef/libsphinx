/*
    @copyright 2018-2021, sphinx@ctrlc.hu
    This file is part of libsphinx.

    SPDX-FileCopyrightText: 2018-21, Stefan Marsiske
    SPDX-License-Identifier: LGPL-3.0-or-later

    libsphinx is free software: you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libsphinx is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libsphinx. If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>

#include "charsets.h"

static const int chars_size[]={
// 0   0
  0,
// 1                  26
  26,
// 2             26
  26,
// 3             26 + 26
  52,
// 4        33
  33,
// 5        33        26
  59,
// 6        33 + 26
  59,
// 7        33 + 26 + 26
  85,
// 8   10
  10,
// 9   10 +           26
  36,
// a   10 +      26
  36,
// b   10 +      26 + 26
  62,
// c   10 + 33
  43,
// d   10 + 33 +      26
  69,
// e   10 + 33 + 26
  69,
// f   10 + 33 + 26 + 26
  95
};


static void usage(const char* prg) {
  fprintf(stderr,"usage: %s <u|l|s|d> <size>\n", prg);
  exit(1);
}

static long tolong(const char* str) {
  char *endptr;
  long val;
  errno = 0;
  val = strtol(str, &endptr, 10);

  /* Check for various possible errors */
  if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
    return -1;
  }
  if (endptr == str) {
    return -1;
  }
  return val;
}

static int torules(const char* str, const char *prg) {
  const char *ptr;
  int res=0;
  for(ptr=str;*ptr;ptr++) {
    if(*ptr == 'u' || *ptr == 'U') res|=1<<0;
    else if(*ptr == 'l' || *ptr == 'l') res|=1<<1;
    else if(*ptr == 's' || *ptr == 's') res|=1<<2;
    else if(*ptr == 'd' || *ptr == 'd') res|=1<<3;
    else usage(prg);
  }
  return res;
}

int main(int argc, char** argv) {
  long size=-1;
  int rules=0;
  if(argc>1) {
    size=tolong(argv[1]);
    if(-1==size) rules=torules(argv[1], argv[0]);
    if(argc>2) {
      if(-1==size) size=tolong(argv[2]);
      else rules=torules(argv[2], argv[0]);
      if(-1==size || 0==rules) usage(argv[0]);
    } else if(-1==size && 0==rules) usage(argv[0]);
  }
  if(0==rules) rules=0xf;
  if(-1==size) size=LONG_MAX;
  char chars[chars_size[rules]], *cptr=chars;
  if(rules & 1) {memcpy(cptr,UPPER,sizeof UPPER); cptr+=sizeof UPPER;}
  if(rules & 2) {memcpy(cptr,LOWER,sizeof LOWER); cptr+=sizeof LOWER;}
  if(rules & 4) {memcpy(cptr,SYMBOLS,sizeof SYMBOLS); cptr+=sizeof SYMBOLS;}
  if(rules & 8) {memcpy(cptr,DIGITS,sizeof DIGITS); cptr+=sizeof DIGITS;}

  // start processing stdin
  uint8_t buf[256];
  int rsize;
  int i,j;
  unsigned x=0, y=0;
  while(!feof(stdin) && size>0) {
    rsize=fread(buf, 1, 256, stdin);
    i=0;
    while(size>0 && (i<rsize || x>0)) {
      y=x;
      for(j=3;j>=0 && i<rsize;j--) {
        if(x<(1<<8*j)) y|=((unsigned)(buf[i++]))<<8*j;
        else break;
      }
      x=y;
      ldiv_t q = ldiv(x, chars_size[rules]);
      x=q.quot;
      printf("%c", chars[q.rem]);
      size--;
    }
  }
  printf("\n");
  return 0;
}
