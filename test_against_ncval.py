# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import subprocess

from generator import Byte
import generator


bundle_size = 32

bits = 64


def GetInstructions():
  root = generator.GetRoot(nacl_mode=True)
  root = generator.FilterModRM(root)
  for bytes, label_map in generator.FlattenTrie(root):
    label_map['align_to_end'] = (label_map['instr_name'] == 'call')
    yield bytes, label_map

  # TODO: It would be better if we tested the final DFA, rather than
  # enumerating the superinstructions here separately.
  indirect_jumps = generator.MergeMany(list(generator.SandboxedJumps()),
                                       generator.NoMerge)
  for bytes, label_map in generator.FlattenTrie(indirect_jumps):
    label_map['align_to_end'] = True # Aligns the jmps unnecessarily
    yield bytes, label_map


def Main():
  asm_fh = open('tmp.S', 'w')

  count = 0
  for bytes, label_map in GetInstructions():
    if 'requires_fixup' in label_map:
      # Add the fixup:  "add %r15, %esp/%ebp"
      reg = label_map['requires_fixup']
      assert reg in (4, 5)
      bytes = bytes + map(Byte, [0x4c, 0x01, 0xf8 | reg])
    if 'requires_zeroextend' in label_map:
      reg = label_map['requires_zeroextend']
      # Add the pre-masking:  "movl %reg, %reg"
      modrm = (3 << 6) | ((reg & 7) << 3) | (reg & 7)
      if reg < 8:
        extra = [0x89, modrm]
      else:
        extra = [0x45, 0x89, modrm]
      bytes = map(Byte, extra) + bytes
    # For relative jumps, fill in wildcards with 0 so that the jumps
    # point to somewhere valid.  Otherwise, use a non-zero value to
    # make things more interesting.
    if 'relative_jump' in label_map:
      wildcard_byte = '00'
    else:
      wildcard_byte = '11'
    def MapWildcard(byte):
      if byte == 'XX':
        return wildcard_byte
      else:
        return byte
    bytes = map(MapWildcard, bytes)
    # Put each instruction in a separate bundle for two reasons:
    #  * It is the easiest way to prevent instructions from straddling
    #    bundle boundaries.
    #  * It helps ncval to continue if it hits an unknown instruction.
    padding = ['90'] * (bundle_size - len(bytes))
    if label_map['align_to_end']:
      # The original ncval requires that 'call' instructions are
      # aligned such that they end at an instruction bundle boundary.
      # This is not required for safety, but we humour the validator.
      # See http://code.google.com/p/nativeclient/issues/detail?id=1955
      bytes = padding + bytes
    else:
      bytes = bytes + padding
    escaped_bytes = ''.join('\\x' + byte for byte in bytes)
    asm_fh.write('.ascii "%s"\n' % escaped_bytes)
    count += 1

  asm_fh.close()
  print 'Testing %i instructions' % count
  subprocess.check_call(['i686-nacl-gcc', '-c', '-m%i' % bits,
                         'tmp.S', '-o', 'tmp.o'])
  subprocess.check_call(['i686-nacl-gcc', '-nostartfiles', '-nostdlib',
                         '-Wl,--entry=0', # Suppress warning about _start
                         '-m%i' % bits, 'tmp.o', '-o', 'tmp.exe'])
  # We assume that ncval and ncval_annotate.py are on PATH.
  # Run ncval_annotate.py to get errors with disassembly.
  # Run ncval on its own just in case.
  subprocess.check_call(['ncval_annotate.py', 'tmp.exe'])
  subprocess.check_call(['ncval', 'tmp.exe'], stdout=open(os.devnull, 'w'))
  print 'Passed'


if __name__ == '__main__':
  Main()
