
def Byte(x):
  return '%02x' % x


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


def Sib(mod):
  for index_reg, index_regname in regs32:
    if index_reg == 4:
      # %esp is not accepted in the position '(reg, %esp)'.
      # In this context, register 4 is %eiz (an always-zero value).
      index_regname = '%eiz'
    for scale in (0, 1, 2, 3):
      # 5 is a special case and is not always %ebp.
      # %esi/%edi are missing from headings in table in doc.
      for base_reg, base_regname in regs32:
        if index_regname == '%eiz' and base_regname == '%esp' and scale == 0:
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
        yield [Byte((scale << 6) | (index_reg << 3) | base_reg)] + extra2, desc


def ModRM1(arg_regs):
  yield (0, 5, ['XX'] * 4, 'VALUE32')
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in regs32:
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


def Mov1(arg_regs, arg_size):
  for rest, op1, op2 in ModRM(arg_regs):
    # MOV r/m32,r32
    yield 0x89, 0x88, rest, '%s, %s' % (op1, op2)
    # MOV r32,r/m32
    yield 0x8b, 0x8a, rest, '%s, %s' % (op2, op1)
    # MOV r/m32,imm32
    yield 0xc7, 0xc6, rest + ['XX'] * arg_size, \
        '$VALUE%i, %s' % (arg_size*8, op2)
  yield 0xa1, 0xa0, ['XX'] * 4, 'VALUE32, %s' % arg_regs[0][1]
  yield 0xa3, 0xa2, ['XX'] * 4, '%s, VALUE32' % arg_regs[0][1]
  # MOV reg32,imm32
  for reg, regname in arg_regs:
    yield 0xb8 + reg, 0xb0 + reg, ['XX'] * arg_size, \
        '$VALUE%i, %s' % (arg_size*8, regname)


def Mov():
  for opcode_lw, opcode_b, bytes, desc in Mov1(regs32, 4):
    yield [Byte(opcode_lw)] + bytes, 'movl ' + desc
  for opcode_lw, opcode_b, bytes, desc in Mov1(regs16, 2):
    yield [Byte(0x66), Byte(opcode_lw)] + bytes, 'movw ' + desc
  for opcode_lw, opcode_b, bytes, desc in Mov1(regs8, 1):
    yield [Byte(opcode_b)] + bytes, 'movb ' + desc


seen = set()
all_decodings = {}
for bytes, desc in sorted(Mov()):
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
  tests = {}
  last_encoding = None
  for line in test_data.split('\n'):
    if line == '':
      pass
    elif line.startswith(' '):
      tests[last_encoding].append(line.strip())
    else:
      last_encoding = line
      tests.setdefault(last_encoding, [])
  passed = True
  for encoding, decodings in sorted(tests.iteritems()):
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

Test()
