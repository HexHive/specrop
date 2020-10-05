#!/usr/bin/env python3
import os
import subprocess as oss
import sys

def ensure_dir(name, create_if_noexist):
  if not os.path.exists(name):
    if create_if_noexist:
      os.makedirs(name)
    else:
      sys.exit('Directory: ' + name + ' does not exist')

def main():
  ensure_dir('src', False)
  ensure_dir('data', True)

  oss.run(['make'], cwd = 'src/')
  oss.run(['./orchestrator'], cwd = 'src/')

  # Find output directory (TODO: FIX) and copy source files to it
  all_subdirs = [d for d in ['data/' + d for d in os.listdir('./data/')] if os.path.isdir(d)]
  latest_subdir = max(all_subdirs, key=os.path.getmtime)
  oss.run(['cp', '-r', 'src', latest_subdir])
  print(latest_subdir)

  # Run octave processing script
  oss.run(['cp', 'src/showme.m', '.'], cwd = latest_subdir)
  oss.run(['octave', 'showme.m'], cwd = latest_subdir)

  # Link latest directory to fixed folder
  if os.path.exists('latest'):
    os.unlink('latest')
  os.symlink(latest_subdir, 'latest')

if __name__ == '__main__':
  main()