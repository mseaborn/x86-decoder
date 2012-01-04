# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re
import subprocess

import generator

# This script attempts to list instructions that generator.py does not
# know about (whether whitelisted or not).
#
# It generates instructions by enumerating prefix/opcode combinations
# and feeding them through objdump to see which are valid.


def GetExamples():
  for p_twobyte in [[], [0x0f]]:
    for byte in xrange(256):
      for p_data16 in [[], [0x66]]:
        for p_rep in [[], [0xf2], [0xf3]]:
          yield p_data16 + p_rep + p_twobyte + [byte]
  # Attempt to enumerate possible AMD 3DNow instructions.
  for byte in xrange(256):
    yield [0x0f, 0x0f, 0xff, byte]


# Returns whether the prefix sequence "bytes" appears in the trie
# "node".  This cheats: it just checks whether the trie contains a
# subtree, but it does not check whether the subtree contains any
# accepting nodes.
def TrieContainsPrefix(node, bytes):
  for byte in bytes:
    node = node.children.get(byte)
    if node is None:
      return False
  return True


def Main():
  pad_to = 16
  fh = open('tmp.S', 'w')
  for bytes in GetExamples():
    bytes = bytes + [0x90] * (pad_to - len(bytes))
    fh.write('.ascii "%s"\n' % ''.join('\\x%02x' % byte for byte in bytes))
  fh.close()
  subprocess.check_call(['gcc', '-m32', '-c', 'tmp.S', '-o', 'tmp.o'])

  def GetInstrs():
    proc = subprocess.Popen(['objdump', '-d', 'tmp.o', '-M', 'intel'],
                            stdout=subprocess.PIPE)
    regexp = re.compile('\s*([0-9a-f]+):\s*((\S\S )+)\s*(.*)')
    for line in proc.stdout:
      match = regexp.match(line)
      if match is not None:
        addr = int(match.group(1), 16)
        if addr % pad_to == 0:
          bytes = match.group(2).split()
          instr = match.group(4)
          yield instr

  root_node = generator.ExpandWildcards(generator.ConvertToDfa(
      generator.GetRoot(nacl_mode=False)))
  for bytes, instr in zip(GetExamples(), GetInstrs()):
    if '(bad)' in instr:
      continue
    if any(x in instr for x in ('repz ', 'repnz ', 'data16')):
      continue
    bytes = ['%02x' % byte for byte in bytes]
    if not TrieContainsPrefix(root_node, bytes):
      print '%s:%s' % (' '.join(bytes), instr)


if __name__ == '__main__':
  Main()
