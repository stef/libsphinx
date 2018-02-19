#!/usr/bin/env python3

import os, configparser

def getcfg(app):
  config = configparser.ConfigParser()
  # read global cfg
  config.read('/etc/sphinx/config')
  # update with per-user configs
  config.read(os.path.expanduser("~/.sphinxrc"))
  config.read(os.path.expanduser("~/.config/sphinx/config"))
  # over-ride with local directory config
  config.read(os.path.expanduser("sphinx.cfg"))
  return config

if __name__ == '__main__':
  import sys
  getcfg('sphinx').write(sys.stdout)
