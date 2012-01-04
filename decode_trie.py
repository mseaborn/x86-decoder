# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

import objdump


def CheckInstr(trie, bytes):
  node = trie['start']
  for byte in bytes:
    if 'XX' in trie['map'][node]:
      node = trie['map'][node]['XX']
    elif byte in trie['map'][node]:
      node = trie['map'][node][byte]
    else:
      return False
  return trie['accepts'][node]


def Format(string):
  return ' '.join('%02x' % ord(byte) for byte in string)


def Main(args):
  assert len(args) == 2
  trie_file = args[0]
  obj_file = args[1]

  trie = eval(open(trie_file, 'r').read(), {})

  for bytes, disasm in objdump.Decode(obj_file):
    ok = CheckInstr(trie, ['%02x' % ord(byte) for byte in bytes])
    if disasm.startswith('j') or 'call' in disasm:
      ok = 'Jump'
    print ok, disasm, Format(bytes)


if __name__ == '__main__':
  Main(sys.argv[1:])
