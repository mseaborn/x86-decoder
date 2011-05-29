
import atexit
import os
import re
import subprocess
import sqlite3

import objdump


def write_file(filename, data):
  fh = open(filename, "w")
  try:
    fh.write(data)
  finally:
    fh.close()


def EncodeUncached(instr):
  write_file('tmp.S', instr + '\n')
  rc = subprocess.call(['as', '--32', 'tmp.S', '-o', 'tmp.o'])
  if rc != 0:
    raise Exception('Failed to encode %r' % instr)
  proc = subprocess.Popen(['objdump', '-d', 'tmp.o'],
                          stdout=subprocess.PIPE)
  lines = list(proc.stdout)
  assert proc.wait() == 0
  got = []
  for line in lines:
    match = re.match('\s*[0-9a-f]+:\s*((\S\S )+)\s*(.*)', line)
    if match is not None:
      bytes = match.group(1)
      disasm = match.group(3)
      bytes = [chr(int(part, 16)) for part in bytes.strip().split(' ')]
      got.extend(bytes)
  return got


def InitDb(db):
  db.execute('create table encoding (instr, bytes)')
  db.execute('create index encoding_instr on encoding (instr);')
# Test
InitDb(sqlite3.connect(':memory:'))

db_file = 'cache.sqlite'
db_is_new = not os.path.exists(db_file)
db = sqlite3.connect(db_file)
if db_is_new:
  InitDb(db)
db.text_factory = str
atexit.register(db.commit)


asm_cache = {}

def Encode(instr):
  if instr in asm_cache:
    return list(asm_cache[instr])
  for bytes, in db.execute('select bytes from encoding where instr = ?',
                           (instr,)):
    return eval(bytes, {})
  bytes = EncodeUncached(instr)
  db.execute('insert into encoding values (?, ?)', (instr, repr(bytes)))
  return bytes


def assert_eq(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))


assert_eq(Encode('movl $0x12345678, 0x12345678(%eax)'),
          list('\xc7\x80\x78\x56\x34\x12\x78\x56\x34\x12'))


def FormatByte(arg):
  if arg == 'XX':
    return arg
  return '%02x' % ord(arg)


def Matches(string, substr):
  i = 0
  while True:
    index = string.find(substr, i)
    if index == -1:
      return
    yield index
    i = index + len(substr)


def DiscoverArg(instr_template, index):
  def Try(value, value_str):
    copy = instr_template[:]
    copy[index] = value
    bytes = Encode(''.join(copy))
    bytes_str = ''.join(bytes)
    return bytes, set(Matches(bytes_str, value_str))

  if instr_template[index] == 'VALUE32':
    bytes1, indexes1 = Try('0x12345678', '\x78\x56\x34\x12')
    bytes2, indexes2 = Try('0x12345679', '\x79\x56\x34\x12')
    op_size = 4
  elif instr_template[index] == 'VALUE16':
    bytes1, indexes1 = Try('0x1234', '\x34\x12')
    bytes2, indexes2 = Try('0x2143', '\x43\x21')
    op_size = 2
  elif instr_template[index] == 'VALUE8':
    bytes1, indexes1 = Try('0x12', '\x12')
    bytes2, indexes2 = Try('0x21', '\x21')
    op_size = 1
  else:
    raise AssertionError('Unknown op_size: %r' % instr_template[index])
  both = indexes1.intersection(indexes2)
  assert_eq(len(both), 1)
  index = list(both)[0]

  indexes = range(index, index + op_size)
  def Erase(bytes):
    for i in indexes:
      bytes[i] = 'XX'
  Erase(bytes1)
  Erase(bytes2)
  assert bytes1 == bytes2
  return bytes1, indexes

assert_eq(DiscoverArg(['and $', 'VALUE32', ', %ebx'], 1),
          (['\x81', '\xe3', 'XX', 'XX', 'XX', 'XX'], [2, 3, 4, 5]))
assert_eq(DiscoverArg(['and $', 'VALUE16', ', %ebx'], 1),
          (['\x81', '\xe3', 'XX', 'XX', '\x00', '\x00'], [2, 3]))
assert_eq(DiscoverArg(['and $', 'VALUE8', ', %ebx'], 1),
          (['\x83', '\xe3', 'XX'], [2]))


def DiscoverArgs2(template, index1, index2):
  dummies = {
    'VALUE32': '0x11111111',
    'VALUE16': '0x1111',
    'VALUE8': '0x11',
    }
  copy1 = template[:]
  copy1[index2] = dummies[template[index2]]
  copy2 = template[:]
  copy2[index1] = dummies[template[index1]]

  bytes1, indexes1 = DiscoverArg(copy1, index1)
  bytes2, indexes2 = DiscoverArg(copy2, index2)

  def Erase(bytes, indexes):
    for i in indexes:
      assert bytes[i] == '\x11'
      bytes[i] = 'XX'
  Erase(bytes1, indexes2)
  Erase(bytes2, indexes1)
  assert bytes1 == bytes2
  return bytes1

assert_eq(DiscoverArgs2(['movl $', 'VALUE32', ', ', 'VALUE32', '(%ebx)'],
                        1, 3),
          ['\xc7', '\x83', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX'])
assert_eq(DiscoverArgs2(['movl $', 'VALUE32', ', ', 'VALUE8', '(%ebx)'],
                        1, 3),
          ['\xc7', '\x43', 'XX', 'XX', 'XX', 'XX', 'XX'])


def Tokenise1(string):
  regexp = re.compile('[a-zA-Z_0-9]+')
  i = 0
  while i < len(string):
    match = regexp.search(string, i)
    if match is None:
      yield string[i:]
      break
    else:
      if match.start() > 0:
        yield string[i:match.start()]
      yield match.group()
      i = match.end()

def Tokenise(string):
  return [token for token in Tokenise1(string)
          if token.strip() != '##']

assert_eq(list(Tokenise('FOO + BAR')), ['FOO', ' + ', 'BAR'])
assert_eq(list(Tokenise('(FOO + BAR)')), ['(', 'FOO', ' + ', 'BAR', ')'])
assert_eq(list(Tokenise('FOO ## BAR')), ['FOO', 'BAR'])


top_prods = {}

def AddProd(lhs, rhs):
  top_prods[lhs] = [tuple(Tokenise(string)) for string in rhs]

# No need for VALUE16 here because 'l' instructions don't use 16-bit
# immediates, only 8-bit and 32-bit.
AddProd('VALUE', ('VALUE8', 'VALUE32'))
AddProd('IMMEDIATE16', ('VALUE8', 'VALUE16'))
AddProd('MEM', ('(REG32)',
                'VALUE(REG32)',
                '(REG32, REG32_NOT_ESP, MUL)',
                'VALUE(REG32, REG32_NOT_ESP, MUL)'
                ))
AddProd('MUL', ('1', '2', '4', '8'))
AddProd('MEM_OR_REG32', ('MEM', 'REG32'))
AddProd('MEM_OR_REG16', ('MEM', 'REG16'))
AddProd('MEM_OR_REG8', ('MEM', 'REG8'))
AddProd('REG32',
        ('%eax',
         '%ebx',
         '%ecx',
         '%edx',
         '%esi',
         '%edi',
         '%ebp',
         '%esp'))
AddProd('REG32_NOT_ESP',
        ('%eax',
         '%ebx',
         '%ecx',
         '%edx',
         '%esi',
         '%edi',
         '%ebp'))
AddProd('REG16', ('%ax',
                  '%bx',
                  '%cx',
                  '%dx',
                  '%si',
                  '%di',
                  '%sp',
                  '%bp',
                  ))
AddProd('REG8', ('%al',
                 '%bl',
                 '%cl',
                 '%dl',
                 '%ah',
                 '%bh',
                 '%ch',
                 '%dh'))
AddProd('SRC_DEST', ('l $VALUE, MEM_OR_REG32',
                     'l REG32, MEM_OR_REG32',
                     'l MEM, REG32',
                     'w $IMMEDIATE16, MEM_OR_REG16',
                     'w REG16, MEM',
                     'w MEM, REG16',
                     'w REG16, REG16',
                     'b $VALUE8, MEM_OR_REG8',
                     'b REG8, MEM',
                     'b MEM, REG8',
                     'b REG8, REG8',
                     # Not allowed:
                     # MEM, MEM
                     # MEM, $VALUE
                     ))
# Like SRC_DEST but without any immediate values.
AddProd('SRC_DEST_WRITABLE',
        ('l REG32, MEM_OR_REG32',
         'l MEM, REG32',
         'w REG16, MEM',
         'w MEM, REG16',
         'w REG16, REG16',
         'b REG8, MEM',
         'b MEM, REG8',
         'b REG8, REG8',
         ))
# For zero/sign-extended move.
AddProd('EXTEND_MOVE',
        ('bw MEM_OR_REG8, REG16',
         'bl MEM_OR_REG8, REG32',
         'wl MEM_OR_REG16, REG32'))
AddProd('SHIFT_ARG',
        ('', # Shift by 1.  Same as $1, but with a different encoding.
         '%cl, ', # Shift instructions can only use %cl as the shift arg.
         '$VALUE8, '))
AddProd('SHIFT_ARGS',
        ('l SHIFT_ARG MEM_OR_REG32',
         'w SHIFT_ARG MEM_OR_REG16',
         'b SHIFT_ARG MEM_OR_REG8'))
AddProd('DSHIFT_ARGS',
        ('l $VALUE8, REG32, MEM_OR_REG32',
         'l %cl, REG32, MEM_OR_REG32',
         'w $VALUE8, REG16, MEM_OR_REG16',
         'w %cl, REG16, MEM_OR_REG16'))
AddProd('BIT_SCAN_ARGS',
        ('l MEM_OR_REG32, REG32',
         'w MEM_OR_REG16, REG16'))
AddProd('UNARY_ARG',
        ('l MEM_OR_REG32',
         'w MEM_OR_REG16',
         'b MEM_OR_REG8'))
# 'mul' and 'div' always use %eax/%ax/%al.  We specify it explicitly
# here to be clearer, although gas allows the operand to be omitted.
AddProd('DIV_ARGS',
        ('l MEM_OR_REG32, %eax',
         'w MEM_OR_REG16, %ax',
         'b MEM_OR_REG8, %al'))
# gas doesn't allow specifying the implicit arg for 'mul' though.
AddProd('MUL_ARGS',
        ('l MEM_OR_REG32',
         'w MEM_OR_REG16',
         'b MEM_OR_REG8'))
AddProd('IMUL_ARGS',
        ('MUL_ARGS',
         'l MEM_OR_REG32, REG32',
         'l $VALUE, REG32',
         'l $VALUE, MEM_OR_REG32, REG32',
         'w MEM_OR_REG16, REG16',
         'w $IMMEDIATE16, REG16',
         'w $IMMEDIATE16, MEM_OR_REG16, REG16'))
# 'pe' is an alias for 'p'
# 'po' is an alias for 'np'
AddProd('CONDITION',
        ('a', 'ae', 'b', 'be', 'c', 'e', 'g', 'ge',
         'l', 'le', 'o', 'p', 's', 'z',
         # Negations:
         'na', 'nae', 'nb', 'nbe', 'nc', 'ne', 'ng', 'nge',
         'nl', 'nle', 'no', 'np', 'ns', 'nz',
         ))
AddProd('REPEAT',
        ('', 'rep', 'repe', 'repz', 'repne', 'repnz'))


def Generate(prods, instr):
  if len(instr) == 0:
    yield []
    return
  token = instr[0]
  if token in prods:
    vals = (x for toks in prods[token]
            for x in Generate(prods, toks))
  else:
    vals = [[token]]
  for val in vals:
    for rest in Generate(prods, instr[1:]):
      yield val + rest


def TryInstr(instr):
  indexes = [index for index, token in enumerate(instr)
             if token.startswith('VALUE')]

  if len(indexes) == 0:
    return Encode(''.join(instr))
  elif len(indexes) == 1:
    bytes, i = DiscoverArg(instr, indexes[0])
    return bytes
  elif len(indexes) == 2:
    return DiscoverArgs2(instr, indexes[0], indexes[1])
  else:
    assert 0

assert_eq(TryInstr(['hlt']), ['\xf4'])
assert_eq(TryInstr(['and $', 'VALUE8', ', %ebx']),
          ['\x83', '\xe3', 'XX'])
assert_eq(TryInstr(['movl $', 'VALUE32', ', ', 'VALUE8', '(%ebx)']),
          ['\xc7', '\x43', 'XX', 'XX', 'XX', 'XX', 'XX'])


templates = [
  'nop',
  'hlt',
  'cld',
  'std',
  'cltd', # Also known as 'cwd' or 'cdq' in Intel syntax.
  'pushl MEM_OR_REG32',
  'pushl $VALUE',
  'popl MEM_OR_REG32',
  'add ## SRC_DEST',
  'adc ## SRC_DEST',
  'sub ## SRC_DEST',
  'sbb ## SRC_DEST',
  'and ## SRC_DEST',
  'or  ## SRC_DEST',
  'xor ## SRC_DEST',
  'cmp ## SRC_DEST',
  'test ## SRC_DEST',
  'mov ## SRC_DEST',
  'movs ## EXTEND_MOVE', # Sign-extend.  Known as 'movsx' in Intel syntax.
  'movz ## EXTEND_MOVE', # Zero-extend.  Known as 'movzx' in Intel syntax.
  'xchg ## SRC_DEST_WRITABLE',
  #'xchg REG32, MEM_OR_REG32',
  #'xchg MEM, REG32', # Redundant
  'shl ## SHIFT_ARGS', # 'sal' is a synonym.
  'shr ## SHIFT_ARGS',
  'sar ## SHIFT_ARGS',
  'shld ## DSHIFT_ARGS',
  'shrd ## DSHIFT_ARGS',
  'bsr ## BIT_SCAN_ARGS',
  'bsf ## BIT_SCAN_ARGS',
  'neg ## UNARY_ARG',
  'not ## UNARY_ARG',
  'inc ## UNARY_ARG',
  'dec ## UNARY_ARG',
  'div ## DIV_ARGS',
  'idiv ## DIV_ARGS',
  'mul ## MUL_ARGS',
  'imul ## IMUL_ARGS',
  'set ## CONDITION REG8',
  'set ## CONDITION MEM',
  'lea MEM, REG32', # includes pointless 'lea (%eax), %eax'
  # Is this form specific to 'lea'?
  'lea VALUE(, REG32_NOT_ESP, MUL), REG32',
  'REPEAT movsb %ds:(%esi), %es:(%edi)',
  'REPEAT movsw %ds:(%esi), %es:(%edi)',
  'REPEAT movsl %ds:(%esi), %es:(%edi)', # 'movsd' in Intel syntax.
  'REPEAT cmpsb %es:(%edi), %ds:(%esi)',
  'REPEAT cmpsw %es:(%edi), %ds:(%esi)',
  'REPEAT cmpsl %es:(%edi), %ds:(%esi)',
  'REPEAT stosb %al, %es:(%edi)',
  'REPEAT stosw %ax, %es:(%edi)',
  'REPEAT stosl %eax, %es:(%edi)',
  'REPEAT scasb %es:(%edi), %al',
  'REPEAT scasw %es:(%edi), %ax',
  'REPEAT scasl %es:(%edi), %eax',
  ]


def FormatBytes(bytes):
  return ' '.join(FormatByte(byte) for byte in bytes)


def PrimeCache():
  tmp_prods = top_prods.copy()
  def AddProd2(lhs, rhs):
    tmp_prods[lhs] = [tuple(Tokenise(string)) for string in rhs]
  AddProd2('VALUE8', ('0x11', '0x12', '0x21'))
  AddProd2('VALUE16', ('0x1111', '0x1234', '0x2143'))
  AddProd2('VALUE32', ('0x11111111', '0x12345678', '0x12345679'))
  fh = open('all.S', 'w')
  instrs = []
  for template in templates:
    for instr in Generate(tmp_prods, list(Tokenise(template))):
      instr_str = ''.join(instr)
      fh.write(instr_str + '\n')
      instrs.append(instr_str)
  fh.close()
  print '%i instructions' % len(instrs)
  subprocess.check_call(['gcc', '-m32', '-c', 'all.S', '-o', 'all.o'])
  print 'run objdump...'
  dumped = list(objdump.Decode('all.o'))
  assert_eq(len(instrs), len(dumped))
  for instr, (bytes, disasm) in zip(instrs, dumped):
    asm_cache[instr] = bytes

print 'priming cache...'
PrimeCache()

print 'generate...'
fh = open('patterns.tmp', 'w')
for template in templates:
  for instr in Generate(top_prods, list(Tokenise(template))):
    bytes = TryInstr(instr)
    instr_str = ''.join(instr)
    fh.write('%s:%s\n' % (FormatBytes(bytes), instr_str))
    #print '%s    %s' % (instr_str, FormatBytes(bytes))
# Long nops
# Why do we have two different long nops of the same length?
fh.write('''\
8d b4 26 00 00 00 00:lea 0x0(%esi,%eiz,1),%esi
8d bc 27 00 00 00 00:lea 0x0(%edi,%eiz,1),%edi
8d 74 26 00:lea 0x0(%esi,%eiz,1),%esi
''')
fh.close()
os.rename('patterns.tmp', 'patterns')
