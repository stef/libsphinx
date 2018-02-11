#!/usr/bin/env python3
#
# This file is part of WebSphinx.
# Copyright (C) 2018 pitchfork@ctrlc.hu
#
# WebSphinx is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# WebSphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

import subprocess
import os, sys, struct, json
from sphinx import datadir, SphinxHandler

def getpwd():
    proc=subprocess.Popen(['pinentry-gtk-2', '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input='SETTITLE sphinx master password prompt\nSETPROMPT sphinx master password\ngetpin\n'.encode())
    if proc.returncode == 0:
        for line in out.split(b'\n'):
            if line.startswith(b"D "): return line[2:]
        #    if line.startswith(b"ERR 83886179 Operation cancelled"): return None
        #print("wtf")
        #print('out',out)
        #print('err',err)
    #else:
    #    print("returned non-zero", err)

# Send message using Native messaging protocol
def send_message(data):
  msg = json.dumps(data).encode('utf-8')
  length = struct.pack('@I', len(msg))
  sys.stdout.buffer.write(length)
  sys.stdout.buffer.write(msg)
  sys.stdout.buffer.flush()

def users(data):
  #log.write(repr(data).encode())
  #log.write(b'\n')
  handler = SphinxHandler(datadir)
  res = {'names': [i.decode() for i in handler.list(data['site'])],
         'cmd': 'list',
         'site': data['site']}
  #log.write(repr(res).encode())
  #log.write(b'\n')
  send_message({ 'results': res })

def get(data):
  #log.write(repr(data).encode())
  #log.write(b'\n')
  #send_message({ 'password': "w L')qX_QLwD\\%^A2]y!Hbo4>xYU*]M</VM3u?uA", 'name': data['name'], 'site': data['site']})
  handler = SphinxHandler(datadir)
  pwd=getpwd()
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'show'}
    send_message({ 'results': res })
    #log.write(repr(res).encode())
    #log.write(b'\n')
  handler.get(callback, pwd, data['name'], data['site'])

def main():
  while True:
    # Read message using Native messaging protocol
    length_bytes = sys.stdin.buffer.read(4)
    if len(length_bytes) == 0:
      return

    length = struct.unpack('i', length_bytes)[0]
    data = json.loads(sys.stdin.buffer.read(length).decode('utf-8'))

    if data['cmd'] == 'show':
      get(data)
    elif data['cmd'] == 'list':
      users(data)

if __name__ == '__main__':
  #log = open('/tmp/websphinx.log','a+b')
  main()
