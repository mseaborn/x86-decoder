
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
  (7, '%rdi'),
  (8, '%r8'),
  (9, '%r9'),
  (10, '%r10'),
  (11, '%r11'),
  (12, '%r12'),
  (13, '%r13'),
  (14, '%r14'),
  (15, '%r15'))

regs32 = (
  (0, '%eax'),
  (1, '%ecx'),
  (2, '%edx'),
  (3, '%ebx'),
  (4, '%esp'),
  (5, '%ebp'),
  (6, '%esi'),
  (7, '%edi'),
  (8, '%r8d'),
  (9, '%r9d'),
  (10, '%r10d'),
  (11, '%r11d'),
  (12, '%r12d'),
  (13, '%r13d'),
  (14, '%r14d'),
  (15, '%r15d'))

regs16 = (
  (0, '%ax'),
  (1, '%cx'),
  (2, '%dx'),
  (3, '%bx'),
  (4, '%sp'),
  (5, '%bp'),
  (6, '%si'),
  (7, '%di'),
  (8, '%r8w'),
  (9, '%r9w'),
  (10, '%r10w'),
  (11, '%r11w'),
  (12, '%r12w'),
  (13, '%r13w'),
  (14, '%r14w'),
  (15, '%r15w'))

# 8-bit registers accessible with no REX prefix.
# These can be the low or high 8 bits of a 16-bit register.
regs8_original = (
  (0, '%al'),
  (1, '%cl'),
  (2, '%dl'),
  (3, '%bl'),
  (4, '%ah'),
  (5, '%ch'),
  (6, '%dh'),
  (7, '%bh'))

# 8-bit registers accessible with a REX prefix.
# These are always the low 8 bits of a larger register.
regs8_extended = (
  (0, '%al'),
  (1, '%cl'),
  (2, '%dl'),
  (3, '%bl'),
  (4, '%spl'),
  (5, '%bpl'),
  (6, '%sil'),
  (7, '%dil'),
  (8, '%r8b'),
  (9, '%r9b'),
  (10, '%r10b'),
  (11, '%r11b'),
  (12, '%r12b'),
  (13, '%r13b'),
  (14, '%r14b'),
  (15, '%r15b'))

mem_regs = regs64
zero_reg = '%riz'


def RegTop(reg):
  assert 0 <= reg and reg < 16
  return (reg >> 3) & 1

def RegBottom(reg):
  assert 0 <= reg and reg < 16
  return reg & 7


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
        # If index_regname == '%eiz' and base_regname == '%esp'
        if index_reg == 4 and RegBottom(base_reg) == 4 and scale == 0:
          index_result = ''
        else:
          index_result = ', %s, %s' % (index_regname, 1 << scale)
        if RegBottom(base_reg) == 5 and mod == 0:
          base_regname = ''
          extra = 'VALUE32'
          extra2 = ['XX'] * 4
        else:
          extra = ''
          extra2 = []
        desc = '%s(%s%s)' % (extra, base_regname, index_result)
        # If index_regname == '%eiz' and base_regname == ''.
        if (index_reg == 4 and
            RegBottom(base_reg) == 5 and mod == 0 and scale == 0):
          desc = extra
        yield (RegTop(index_reg) << 1) | RegTop(base_reg), \
            [Byte((scale << 6) |
                  (RegBottom(index_reg) << 3) |
                  RegBottom(base_reg))] \
            + extra2, desc


# yields (rex_bits, mod, reg, bytes, desc)
def ModRM1(arg_regs):
  yield (0, 0, 5, ['XX'] * 4, 'VALUE32(%rip)')
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in mem_regs:
      if RegBottom(reg2) == 4:
        # %esp is not accepted in this position.
        # 4 is a special value: adds SIB byte.
        continue
      if RegBottom(reg2) == 5 and mod == 0:
        continue
      yield (RegTop(reg2), mod, RegBottom(reg2), ['XX'] * dispsize,
             '%s(%s)' % (disp_str, regname2))
    reg2 = 4
    for rex_bits, sib_bytes, desc in Sib(mod):
      yield (rex_bits, mod, reg2, sib_bytes + ['XX'] * dispsize,
             disp_str + desc)
  mod = 3
  for reg2, regname2 in arg_regs:
    yield (RegTop(reg2), mod, RegBottom(reg2), [], regname2)


def ModRM(arg_regs):
  for reg, regname in arg_regs:
    for rex_bits, mod, reg2, rest, desc in ModRM1(arg_regs):
      yield ((RegTop(reg) << 2) | rex_bits,
             [Byte((mod << 6) | (RegBottom(reg) << 3) | reg2)] + rest,
             regname, desc)


def ModRMSingleArg(arg_regs, opcode):
  for rex_bits, mod, reg2, rest, desc in ModRM1(arg_regs):
    yield (rex_bits, [Byte((mod << 6) | (opcode << 3) | reg2)] + rest, desc)


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
      for rex_bits, rest, op1, op2 in ModRM(arg_regs):
        yield rex_bits, opcode_lw, opcode_b, rest, instr, '%s, %s' % (op1, op2)
    elif args == 'mem reg':
      assert modrm_opcode is None
      for rex_bits, rest, op1, op2 in ModRM(arg_regs):
        yield rex_bits, opcode_lw, opcode_b, rest, instr, '%s, %s' % (op2, op1)
    elif args == 'imm mem':
      for rex_bits, rest, op in ModRMSingleArg(arg_regs, modrm_opcode):
        yield rex_bits, opcode_lw, opcode_b, rest + ['XX'] * arg_size, \
            instr, '$VALUE%i, %s' % (arg_size*8, op)
    elif args == 'imm8 mem':
      for rex_bits, rest, op in ModRMSingleArg(arg_regs, modrm_opcode):
        yield rex_bits, opcode_lw, opcode_b, rest + ['XX'], \
            instr, '$VALUE8, %s' % op
    else:
      raise AssertionError('Unknown pattern: %r' % args)

  yield 0, 0xa1, 0xa0, ['XX'] * 8, 'mov', 'VALUE64, %s' % arg_regs[0][1]
  yield 0, 0xa3, 0xa2, ['XX'] * 8, 'mov', '%s, VALUE64' % arg_regs[0][1]
  # MOV reg32,imm32
  for reg, regname in arg_regs:
    yield RegTop(reg), 0xb8 + RegBottom(reg), 0xb0 + RegBottom(reg), \
        ['XX'] * arg_size2, \
        'mov', '$VALUE%i, %s' % (arg_size2*8, regname)

  # yield 0x05, 0x04, ['XX'] * arg_size, 'add', \
  #     '$VALUE%i, %s' % (arg_size*8, arg_regs[0][1])
  # yield 0x2d, 0x2c, ['XX'] * arg_size, 'sub', \
  #     '$VALUE%i, %s' % (arg_size*8, arg_regs[0][1])


def Generate2():
  for rex_bits, opcode_lw, opcode_b, bytes, instr, desc in \
        Generate1(regs64, 4, 8):
    yield (1 << 3) | rex_bits, \
        [], [Byte(opcode_lw)] + bytes, instr + 'q ' + desc
  for rex_bits, opcode_lw, opcode_b, bytes, instr, desc in \
        Generate1(regs32, 4, 4):
    yield rex_bits, [], [Byte(opcode_lw)] + bytes, instr + 'l ' + desc
  for rex_bits, opcode_lw, opcode_b, bytes, instr, desc in \
        Generate1(regs16, 2, 2):
    yield rex_bits, [Byte(0x66)], [Byte(opcode_lw)] + bytes, instr + 'w ' + desc
  for rex_bits, opcode_lw, opcode_b, bytes, instr, desc in \
        Generate1(regs8_original, 1, 1):
    if rex_bits == 0 and opcode_b is not None:
      yield rex_bits, [], [Byte(opcode_b)] + bytes, instr + 'b ' + desc
  for rex_bits, opcode_lw, opcode_b, bytes, instr, desc in \
        Generate1(regs8_extended, 1, 1):
    if rex_bits != 0 and opcode_b is not None:
      yield rex_bits, [], [Byte(opcode_b)] + bytes, instr + 'b ' + desc


def Generate():
  for rex_bits, size_prefix, bytes, desc in Generate2():
    if rex_bits == 0:
      yield size_prefix + bytes, desc
    else:
      yield size_prefix + [Byte(0x40 | rex_bits)] + bytes, desc


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
    asm = '.ascii "%s" /* %s */\n' % (
      ''.join('\\x' + MapWildcard(byte) for byte in bytes), desc)
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
