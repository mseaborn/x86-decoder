
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


def Sib(mod):
  for index_reg, index_regname in ((0, '%eax'),
                                   (1, '%ecx'),
                                   (2, '%edx'),
                                   (3, '%ebx'),
                                   (4, '%eiz'), # special case
                                   (5, '%ebp'),
                                   (6, '%esi'),
                                   (7, '%edi')):
    for scale, scaleval in ((0, 1),
                            (1, 2),
                            (2, 4),
                            (3, 8)):
      # 5 is a special case and is not always %ebp.
      # %esi/%edi are missing from headings in table in doc.
      for base_reg, base_regname in regs32:
        if index_regname == '%eiz':
          if base_regname == '%esp':
            index_result = ''
            if scaleval != 1:
              # non-canonical
              continue
          else:
            index_result = ', %eiz' # non-canonical
            continue
        else:
          index_result = ', %s, %s' % (index_regname, scaleval)
        if base_reg == 5 and mod == 0:
          base_regname = ''
          extra = 'VALUE32'
          extra2 = ['XX'] * 4
        else:
          extra = ''
          extra2 = []
        desc = '%s(%s%s)' % (extra, base_regname, index_result)
        yield [Byte((scale << 6) | (index_reg << 3) | base_reg)] + extra2, desc


def ModRM1():
  yield (0, 5, ['XX'] * 4, 'VALUE32')
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in ((0, '%eax'),
                           (1, '%ecx'),
                           (2, '%edx'),
                           (3, '%ebx'),
                           # 4, handled below: adds SIB byte
                           (5, '%ebp'), # only for mod != 0
                           (6, '%esi'),
                           (7, '%edi')):
      if reg2 == 5 and mod == 0:
        continue
      yield (mod, reg2, ['XX'] * dispsize,
             '%s(%s)' % (disp_str, regname2))
    reg2 = 4
    for sib_bytes, desc in Sib(mod):
      yield (mod, reg2, sib_bytes + ['XX'] * dispsize,
             disp_str + desc)
  mod = 3
  for reg2, regname2 in regs32:
    yield (mod, reg2, [], regname2)


def ModRM():
  for reg, regname in enumerate(('%eax', '%ecx', '%edx', '%ebx',
                                 '%esp', '%ebp', '%esi', '%edi')):
    for mod, reg2, rest, desc in ModRM1():
      yield ([Byte((mod << 6) | (reg << 3) | reg2)] + rest, regname, desc)


def Mov():
  for rest, op1, op2 in ModRM():
    # MOV r/m32,r32
    yield [Byte(0x89)] + rest, 'movl %s, %s' % (op1, op2)
    # MOV r32,r/m32
    yield [Byte(0x8b)] + rest, 'movl %s, %s' % (op2, op1)
    # MOV r/m32,imm32
    yield [Byte(0xc7)] + rest + ['XX'] * 4, \
        'movl $VALUE32, %s' % op2
  yield [Byte(0xa1)] + ['XX'] * 4, 'movl VALUE32, %eax'
  yield [Byte(0xa3)] + ['XX'] * 4, 'movl %eax, VALUE32'
  # MOV reg32,imm32
  for reg, regname in regs32:
    yield [Byte(0xb8 + reg)] + ['XX'] * 4, 'movl $VALUE32, %s' % regname


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
