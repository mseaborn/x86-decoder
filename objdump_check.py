
import re
import subprocess

import objdump


def MapWildcard(byte):
  if byte == 'XX':
    return '11'
  else:
    return byte


def DisassembleTestCallback(get_instructions, bits):
  asm_fh = open('tmp.S', 'w')
  list_fh = open('tmp.list', 'w')
  count = [0]

  def Callback(bytes, desc):
    escaped_bytes = ''.join('\\x' + MapWildcard(byte) for byte in bytes)
    asm_fh.write('.ascii "%s"\n' % escaped_bytes)
    list_fh.write('%s:%s\n' % (' '.join(bytes), desc))
    count[0] += 1

  get_instructions(Callback)
  asm_fh.close()
  list_fh.close()
  print 'Checking %i instructions...' % count[0]
  subprocess.check_call(['gcc', '-c', '-m%i' % bits, 'tmp.S', '-o', 'tmp.o'])
  seq = objdump.Decode('tmp.o')
  for index, line in enumerate(open('tmp.list')):
    bytes, desc = line.rstrip('\n').split(':', 1)
    bytes = bytes.split(' ')
    bytes2, disasm_orig = seq.next()
    if len(bytes) != len(bytes2):
      print 'Length mismatch (%i): %r %r versus %r %r' % (
        index, bytes2, disasm_orig, bytes, desc)
    disasm = disasm_orig
    # Canonicalise whitespace.
    disasm = re.sub('\s+', ' ', disasm)
    # Remove comments.
    disasm = re.sub('\s+#.*$', '', disasm)
    # Canonicalise jump targets.
    disasm = re.sub('^(jn?[a-z]{1,2}|calll|jmp[lw]?|je?cxz) 0x[0-9a-f]+$',
                    '\\1 JUMP_DEST', disasm)
    disasm = (disasm
              .replace('0x1111111111111111', 'VALUE64')
              .replace('0x11111111', 'VALUE32')
              .replace('0x1111', 'VALUE16')
              .replace('0x11', 'VALUE8')
              .replace(',', ', '))
    # gas accepts a ".s" suffix to indicate a non-canonical
    # reversed-operands encoding.  With "-M suffix", objdump prints
    # this.
    disasm = disasm.replace('.s ', ' ')
    # Remove trailing space from our zero-arg instructions, e.g. 'nop'.
    # TODO: Don't put the trailing space in.
    desc = desc.rstrip(' ')
    # objdump also puts in trailing whitespace sometimes.
    disasm = disasm.rstrip(' ')
    if desc != disasm:
      print 'Mismatch (%i): %r != %r (%r) (%s)' % (
        index, desc, disasm, disasm_orig, ' '.join(bytes))


def DisassembleTest(get_instructions, bits):
  def Func(callback):
    for bytes, desc in get_instructions():
      callback(bytes, desc)
  DisassembleTestCallback(Func, bits)
