
def Byte(x):
  return '%02x' % x


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
      for base_reg, base_regname in ((0, '%eax'),
                                     (1, '%ecx'),
                                     (2, '%edx'),
                                     (3, '%ebx'),
                                     (4, '%esp'),
                                     (5, '%ebp'), # special case
                                     (6, '%esi'), # missing from table in doc
                                     (7, '%edi'), # missing from table in doc
                                     ):
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
  for reg2, regname2 in ((0, '%eax'),
                         (1, '%ecx'),
                         (2, '%edx'),
                         (3, '%ebx'),
                         (4, '%esp'),
                         (5, '%ebp'),
                         (6, '%esi'),
                         (7, '%edi')):
    yield (mod, reg2, [], regname2)


def ModRM():
  for reg, regname in enumerate(('%eax', '%ecx', '%edx', '%ebx',
                                 '%esp', '%ebp', '%esi', '%edi')):
    for mod, reg2, rest, desc in ModRM1():
      yield ([Byte((mod << 6) | (reg << 3) | reg2)] + rest,
             '%s, %s' % (regname, desc))


def Mov():
  for rest, desc in ModRM():
    yield [Byte(0x89)] + rest, 'movl ' + desc # MOV r/m32,r32


seen = set()
for x, desc in Mov():
  x = tuple(x)
  assert x not in seen, x
  seen.add(x)
  print '%s:%s' % (' '.join(x), desc)
