
import re
import subprocess

import objdump


def Byte(x):
  return '%02x' % x


regs64 = (
  (0, '%rax'),
  (1, '%rcx'),
  (2, '%rdx'),
  (3, '%rbx'),
  (4, '%rsp'),
  (5, '%rbp'),
  (6, '%rsi'),
  (7, '%rdi'))

regs32 = (
  (0, '%eax'),
  (1, '%ecx'),
  (2, '%edx'),
  (3, '%ebx'),
  (4, '%esp'),
  (5, '%ebp'),
  (6, '%esi'),
  (7, '%edi'))

regs16 = (
  (0, '%ax'),
  (1, '%cx'),
  (2, '%dx'),
  (3, '%bx'),
  (4, '%sp'),
  (5, '%bp'),
  (6, '%si'),
  (7, '%di'))

regs8 = (
  (0, '%al'),
  (1, '%cl'),
  (2, '%dl'),
  (3, '%bl'),
  (4, '%ah'),
  (5, '%ch'),
  (6, '%dh'),
  (7, '%bh'))

mem_regs = regs64
zero_reg = '%riz'


def Sib(mod):
  for index_reg, index_regname in mem_regs:
    if index_reg == 4:
      # %esp is not accepted in the position '(reg, %esp)'.
      # In this context, register 4 is %eiz (an always-zero value).
      index_regname = zero_reg
    for scale in (0, 1, 2, 3):
      # 5 is a special case and is not always %ebp.
      # %esi/%edi are missing from headings in table in doc.
      for base_reg, base_regname in mem_regs:
        # index_regname == '%eiz' and base_regname == '%esp'
        if index_reg == 4 and base_reg == 4 and scale == 0:
          index_result = ''
        else:
          index_result = ', %s, %s' % (index_regname, 1 << scale)
        if base_reg == 5 and mod == 0:
          base_regname = ''
          extra = 'VALUE32'
          extra2 = ['XX'] * 4
        else:
          extra = ''
          extra2 = []
        desc = '%s(%s%s)' % (extra, base_regname, index_result)
        # index_regname == '%eiz' and base_regname == ''.
        if index_reg == 4 and base_reg == 5 and mod == 0 and scale == 0:
          desc = extra
        yield [Byte((scale << 6) | (index_reg << 3) | base_reg)] + extra2, desc


def ModRM1(arg_regs):
  yield (0, 5, ['XX'] * 4, 'VALUE32(%rip)')
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in mem_regs:
      if reg2 == 4:
        # %esp is not accepted in this position.
        # 4 is a special value: adds SIB byte.
        continue
      if reg2 == 5 and mod == 0:
        continue
      yield (mod, reg2, ['XX'] * dispsize,
             '%s(%s)' % (disp_str, regname2))
    reg2 = 4
    for sib_bytes, desc in Sib(mod):
      yield (mod, reg2, sib_bytes + ['XX'] * dispsize,
             disp_str + desc)
  mod = 3
  for reg2, regname2 in arg_regs:
    yield (mod, reg2, [], regname2)


def ModRM(arg_regs):
  for reg, regname in arg_regs:
    for mod, reg2, rest, desc in ModRM1(arg_regs):
      yield ([Byte((mod << 6) | (reg << 3) | reg2)] + rest, regname, desc)


def ModRMSingleArg(arg_regs, opcode):
  for mod, reg2, rest, desc in ModRM1(arg_regs):
    yield ([Byte((mod << 6) | (opcode << 3) | reg2)] + rest, desc)


patterns = (
  (0x89, 0x88, 'mov', 'reg mem', None),
  (0x8b, 0x8a, 'mov', 'mem reg', None),
  (0xc7, 0xc6, 'mov', 'imm mem', 0),

  # (0x01, 0x00, 'add', 'reg mem', None),
  # (0x03, 0x02, 'add', 'mem reg', None),
  # (0x81, 0x80, 'add', 'imm mem', 0),
  # (0x83, None, 'add', 'imm8 mem', 0),

  # (0x29, 0x28, 'sub', 'reg mem', None),
  # (0x2b, 0x2a, 'sub', 'mem reg', None),
  # (0x81, 0x80, 'sub', 'imm mem', 5),
  # (0x83, None, 'sub', 'imm8 mem', 5),
  )


def Generate1(arg_regs, arg_size, arg_size2):
  for opcode_lw, opcode_b, instr, args, modrm_opcode in patterns:
    if args == 'reg mem':
      assert modrm_opcode is None
      for rest, op1, op2 in ModRM(arg_regs):
        yield opcode_lw, opcode_b, rest, instr, '%s, %s' % (op1, op2)
    elif args == 'mem reg':
      assert modrm_opcode is None
      for rest, op1, op2 in ModRM(arg_regs):
        yield opcode_lw, opcode_b, rest, instr, '%s, %s' % (op2, op1)
    elif args == 'imm mem':
      for rest, op in ModRMSingleArg(arg_regs, modrm_opcode):
        yield opcode_lw, opcode_b, rest + ['XX'] * arg_size, \
            instr, '$VALUE%i, %s' % (arg_size*8, op)
    elif args == 'imm8 mem':
      for rest, op in ModRMSingleArg(arg_regs, modrm_opcode):
        yield opcode_lw, opcode_b, rest + ['XX'], \
            instr, '$VALUE8, %s' % op
    else:
      raise AssertionError('Unknown pattern: %r' % args)

  yield 0xa1, 0xa0, ['XX'] * 8, 'mov', 'VALUE64, %s' % arg_regs[0][1]
  yield 0xa3, 0xa2, ['XX'] * 8, 'mov', '%s, VALUE64' % arg_regs[0][1]
  # MOV reg32,imm32
  for reg, regname in arg_regs:
    yield 0xb8 + reg, 0xb0 + reg, ['XX'] * arg_size2, \
        'mov', '$VALUE%i, %s' % (arg_size2*8, regname)

  # yield 0x05, 0x04, ['XX'] * arg_size, 'add', \
  #     '$VALUE%i, %s' % (arg_size*8, arg_regs[0][1])
  # yield 0x2d, 0x2c, ['XX'] * arg_size, 'sub', \
  #     '$VALUE%i, %s' % (arg_size*8, arg_regs[0][1])


def Generate():
  for opcode_lw, opcode_b, bytes, instr, desc in Generate1(regs64, 4, 8):
    reg_bits = 1 << 3
    yield [Byte(0x40 + reg_bits),
           Byte(opcode_lw)] + bytes, instr + 'q ' + desc
  for opcode_lw, opcode_b, bytes, instr, desc in Generate1(regs32, 4, 4):
    yield [Byte(opcode_lw)] + bytes, instr + 'l ' + desc
  for opcode_lw, opcode_b, bytes, instr, desc in Generate1(regs16, 2, 2):
    yield [Byte(0x66), Byte(opcode_lw)] + bytes, instr + 'w ' + desc
  for opcode_lw, opcode_b, bytes, instr, desc in Generate1(regs8, 1, 1):
    if opcode_b is not None:
      yield [Byte(opcode_b)] + bytes, instr + 'b ' + desc


seen = set()
all_decodings = {}
for bytes, desc in sorted(Generate()):
  bytes = tuple(bytes)
  assert bytes not in seen, bytes
  seen.add(bytes)
  encoding_list = all_decodings.setdefault(desc, [])
  #if len(encoding_list) == 0:
  #  print '%s:%s' % (' '.join(bytes), desc)
  encoding_list.append(bytes)

# Print instructions with multiple encodings
def PrintMultiple():
  for desc, encodings in sorted(all_decodings.iteritems()):
    if len(encodings) > 1:
      print desc
      for encoding in encodings:
        print '  ' + ' '.join(encoding)
#PrintMultiple()


test_data = open('generator_tests.txt', 'r').read()

def Test():
  tests = []
  current_list = None
  for line in test_data.split('\n'):
    if line == '':
      pass
    elif line.startswith(' '):
      current_list.append(line.strip())
    else:
      current_list = []
      tests.append((line, current_list))
  passed = True
  for encoding, decodings in tests:
    actual = all_decodings.get(encoding, [])
    actual = sorted([' '.join(bytes) for bytes in actual])
    if decodings != actual:
      print '%s:\nEXPECTED:\n%sACTUAL:\n%s' % (
        encoding,
        ''.join('  %s\n' % string for string in decodings),
        ''.join('  %s\n' % string for string in actual))
      passed = False
  if passed:
    print 'PASS'


# Check that the golden file contains correct instructions by running
# it through objdump.
def CheckGoldenFile():
  fh = open('tmp.S', 'w')
  originals = []
  last_encoding = None
  for line in test_data.split('\n'):
    if line.startswith(' '):
      bytes = line.strip().replace('XX', '00').split()
      asm = '.ascii "%s"\n' % ''.join('\\x' + byte for byte in bytes)
      fh.write(asm)
      originals.append((last_encoding, bytes))
    elif line != '':
      last_encoding = line
  fh.close()
  subprocess.check_call(['gcc', '-c', '-m32', 'tmp.S', '-o', 'tmp.o'])
  count = 0
  for (original, original_bytes), (bytes, disasm) in \
        zip(originals, objdump.Decode('tmp.o')):
    if len(original_bytes) != len(bytes):
      print ' '.join(original_bytes)
      print original
      print disasm
      raise Exception('Mismatch')
    count += 1
  assert count == len(originals)


m_bits = '-m64'


def MapWildcard(byte):
  if byte == 'XX':
    return '11'
  else:
    return byte


def DisassembleTest():
  fh = open('tmp.S', 'w')
  for bytes, desc in Generate():
    asm = '.ascii "%s"\n' % ''.join('\\x' + MapWildcard(byte) for byte in bytes)
    fh.write(asm)
  fh.close()
  subprocess.check_call(['gcc', '-c', m_bits, 'tmp.S', '-o', 'tmp.o'])
  seq = objdump.Decode('tmp.o')
  for index, (bytes, desc) in enumerate(Generate()):
    bytes2, disasm_orig = seq.next()
    if len(bytes) != len(bytes2):
      print 'Length mismatch (%i): %r %r versus %r %r' % (
        index, bytes2, disasm_orig, bytes, disasm)
    disasm = (disasm_orig
              .replace('0x1111111111111111', 'VALUE64')
              .replace('0x11111111', 'VALUE32')
              .replace('0x1111', 'VALUE16')
              .replace('0x11', 'VALUE8')
              .replace(',', ', '))
    # Canonicalise whitespace.
    disasm = re.sub('\s+', ' ', disasm)
    # Remove comments.
    disasm = re.sub('\s+#.*$', '', disasm)
    # gas accepts a ".s" suffix to indicate a non-canonical
    # reversed-operands encoding.  With "-M suffix", objdump prints
    # this.
    disasm = disasm.replace('.s ', ' ')
    if desc != disasm:
      print 'Mismatch (%i): %r != %r (%r) (%s)' % (
        index, desc, disasm, disasm_orig, ' '.join(bytes))


#Test()
#CheckGoldenFile()
DisassembleTest()
