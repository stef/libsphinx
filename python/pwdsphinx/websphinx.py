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
import os, sys, struct, json, platform
try:
    from pwdsphinx.sphinx import datadir, SphinxHandler
except ImportError:
    from sphinx import datadir, SphinxHandler

if platform.system() == 'Windows':
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    pinentry=os.path.join(BASE_DIR,'pinentry-qt.exe')
else:
    pinentry='pinentry-gtk-2'

log = False # '/tmp/websphinx.log'

def getpwd(title):
    proc=subprocess.Popen([pinentry, '-g'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(input=('SETTITLE sphinx %spassword prompt\nSETPROMPT sphinx %spassword\ngetpin\n' % (title,title)).encode())
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
  if log:
    log.write(msg)
    log.write(b'\n')
    log.flush()
  length = struct.pack('@I', len(msg))
  sys.stdout.buffer.write(length)
  sys.stdout.buffer.write(msg)
  sys.stdout.buffer.flush()

def users(data):
  try:
    handler = SphinxHandler(datadir)
    users = handler.list(data['site'])
    res = {'names': [i.decode() for i in users],
           'cmd': 'list', "mode": data['mode'],
           'site': data['site']}
    send_message({ 'results': res })
  except:
    send_message({ 'results': 'fail' })

def get(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'login', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    handler = SphinxHandler(datadir)
    pwd=getpwd("current ")
    handler.get(callback, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def create(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'create', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    handler = SphinxHandler(datadir)
    pwd=getpwd("")
    handler.create(callback, pwd, data['name'], data['site'], data['rules'], data['size'])
  except:
    send_message({ 'results': 'fail' })

def change(data):
  def callback(arg):
    res = { 'password': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'change', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    handler = SphinxHandler(datadir)
    pwd=getpwd("new ")
    handler.change(callback, pwd, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def commit(data):
  def callback(arg):
    res = { 'result': arg, 'name': data['name'], 'site': data['site'], 'cmd': 'commit', "mode": data['mode']}
    send_message({ 'results': res })
  try:
    handler = SphinxHandler(datadir)
    handler.commit(callback, data['name'], data['site'])
  except:
    send_message({ 'results': 'fail' })

def main():
  global log
  if log: log = open(log,'ab')
  while True:
    # Read message using Native messaging protocol
    length_bytes = sys.stdin.buffer.read(4)
    if len(length_bytes) == 0:
      return

    length = struct.unpack('i', length_bytes)[0]
    data = json.loads(sys.stdin.buffer.read(length).decode('utf-8'))

    if log:
      log.write(repr(data).encode())
      log.write(b'\n')
      log.flush()
    if data['cmd'] == 'login':
      get(data)
    elif data['cmd'] == 'list':
      users(data)
    elif data['cmd'] == 'create':
      create(data)
    elif data['cmd'] == 'change':
      change(data)
    elif data['cmd'] == 'commit':
      commit(data)

if __name__ == '__main__':
  main()
