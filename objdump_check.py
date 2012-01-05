# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import re
import subprocess
import sys


def MapWildcard(byte):
  if byte == 'XX':
    return '11'
  else:
    return byte


# The assembler does not accept the %eiz syntax for non-canonical encodings.
eiz_regexp = re.compile(r'(eiz|riz)\*[1248]')


def FillOutValues(desc):
  return (desc
          .replace('VALUE32', '0x11111111')
          .replace('VALUE16', '0x1111')
          .replace('VALUE8', '0x11'))


def DisassembleTestCallback(get_instructions, bits):
  # The main purpose of this test is to run instructions through the
  # disassembler.  But we *also* run them through the assembler as a
  # sanity check, because sometimes the assembler is stricter than the
  # disassembler.  For example, the assembler rejects the illegal
  # instruction 'movlpd %xmm7, %xmm7' but the disassembler does not.
  # However, we do not check the assembler's output because encodings
  # can be non-canonical.
  asm_dec_fh = open('tmp_dec.S', 'w')
  asm_enc_fh = open('tmp_enc.S', 'w')
  asm_enc_fh.write('.intel_syntax noprefix\n')
  list_fh = open('tmp.list', 'w')
  count = [0]

  def Callback(bytes, desc):
    escaped_bytes = ''.join('\\x' + MapWildcard(byte) for byte in bytes)
    asm_dec_fh.write('.ascii "%s"\n' % escaped_bytes)
    if eiz_regexp.search(desc) is None and not desc.startswith('FIXME'):
      asm_enc_fh.write(FillOutValues(desc + '\n'))
    list_fh.write('%s:%s\n' % (' '.join(bytes), desc))
    count[0] += 1

  get_instructions(Callback)
  print 'Checking %i instructions...' % count[0]
  # Add a final instruction otherwise we do not catch length
  # mismatches on the last input instruction.
  Callback(['90'], 'nop')
  asm_dec_fh.close()
  asm_enc_fh.close()
  list_fh.close()
  subprocess.check_call(['gcc', '-c', '-m%i' % bits, 'tmp_dec.S',
                         '-o', 'tmp_dec.o'])
  CrossCheck('tmp_dec.o', 'tmp.list')
  subprocess.check_call(['gcc', '-c', '-m%i' % bits, 'tmp_enc.S',
                         '-o', 'tmp_enc.o'])


whitespace_regexp = re.compile('\s+')
comment_regexp = re.compile('\s+#.*$')
jump_regexp = re.compile(
    '^(jn?[a-z]{1,2}|call|jmp[lw]?|je?cxz|loop(e|ne)?) 0x[0-9a-f]+$')
rex_regexp = re.compile(r'rex(\.R?X?B?)? ')


def NormaliseObjdumpDisasm(disasm):
  # Canonicalise whitespace.
  disasm = whitespace_regexp.sub(' ', disasm)
  # Remove comments.  These annotate %rip-relative addressing.
  disasm = comment_regexp.sub('', disasm)
  # Remove prefix annotations like 'rex.RX'.  This indicates that the
  # REX prefix has bits R and X set but the ModRM/SIB bytes don't use
  # these bits.  The original x86 validators allow this anyway.
  disasm = rex_regexp.sub('', disasm)
  # Canonicalise jump targets.
  disasm = jump_regexp.sub('\\1 JUMP_DEST', disasm)
  disasm = (disasm
            .replace('0x1111111111111111', 'VALUE64')
            .replace('0x11111111', 'VALUE32')
            .replace('0x1111', 'VALUE16')
            .replace('0x11', 'VALUE8')
            .replace(',', ', '))
  return disasm


def ReadObjdump(obj_file):
  proc = subprocess.Popen(['objdump', '-M', 'intel', '--prefix-addresses',
                           '-d', obj_file],
                          stdout=subprocess.PIPE)
  regexp = re.compile('0x([0-9a-f]+)\s*')
  for line in proc.stdout:
    match = regexp.match(line)
    if match is not None:
      addr = int(match.group(1), 16)
      disasm = line[match.end():].rstrip()
      yield addr, disasm
  assert proc.wait() == 0, proc.wait()


# objdump outputs 'data16' on a separate line for 'data16 push VALUE8'
# (66 6a XX) even though it is a single instruction.  We need to undo
# this.
def MungeData16(instrs):
  for addr, disasm in instrs:
    if disasm == 'data16':
      addr2, disasm2 = instrs.next()
      disasm = '%s %s' % (disasm, disasm2)
    yield addr, disasm


def ReadListFile(fh):
  for line in fh:
    bytes, desc = line.rstrip('\n').split(':', 1)
    yield bytes.split(' '), desc


def CrossCheck(obj_file, list_file):
  objdump_iter = MungeData16(ReadObjdump(obj_file))
  expected_addr = 0
  prev_length = 0
  failed = False
  for index, (bytes, desc) in enumerate(ReadListFile(open(list_file))):
    got_addr, disasm_orig = objdump_iter.next()
    if got_addr != expected_addr:
      # This only catches mismatches on the previous instruction,
      # which is why we added an extra final instruction earlier.
      print 'Length mismatch on previous instruction: got %i, expected %i' % (
          prev_length + got_addr - expected_addr,
          prev_length)
      failed = True
      break
    expected_addr += len(bytes)
    prev_length = len(bytes)

    disasm = NormaliseObjdumpDisasm(disasm_orig)
    if desc.startswith('FIXME'):
      # Some instructions are not handled correctly by binutils.
      continue
    if desc != disasm:
      print 'Mismatch (%i): %r != %r (%r) (%s)' % (
        index, desc, disasm, disasm_orig, ' '.join(bytes))
      failed = True
  if failed:
    raise Exception('Cross check failed')


def DisassembleTest(get_instructions, bits):
  def Func(callback):
    for bytes, desc in get_instructions():
      callback(bytes, desc)
  DisassembleTestCallback(Func, bits)


def Main(args):
  for filename in args:
    DisassembleTest(lambda: ReadListFile(open(filename, 'r')), 32)


if __name__ == '__main__':
  Main(sys.argv[1:])
