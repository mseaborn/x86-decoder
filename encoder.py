
import atexit
import os
import re
import subprocess
import sqlite3


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


def Encode(instr):
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


def Tokenise(string):
  regexp = re.compile('[A-Z_0-9]+')
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

assert_eq(list(Tokenise('FOO + BAR')), ['FOO', ' + ', 'BAR'])
assert_eq(list(Tokenise('(FOO + BAR)')), ['(', 'FOO', ' + ', 'BAR', ')'])


regs = (
  '%eax',
  '%ebx',
  '%ecx',
  '%edx',
  '%esi',
  '%edi',
  '%ebp',
  '%esp',
  )

prods = {}

def AddProd(lhs, rhs):
  prods[lhs] = [tuple(Tokenise(string)) for string in rhs]

AddProd('VALUE', ('VALUE8', 'VALUE32'))
AddProd('MEM', ('(REG)',
                'VALUE(REG)',
                '(REG, REG_NOT_ESP)',
                'VALUE(REG, REG_NOT_ESP)'
                ))
AddProd('MEM_OR_REG', ('MEM', 'REG'))
AddProd('REG', regs)
AddProd('REG_NOT_ESP', (
  '%eax',
  '%ebx',
  '%ecx',
  '%edx',
  '%esi',
  '%edi',
  '%ebp',
  ))
AddProd('REG_OR_IMM', ('REG', '$VALUE'))
AddProd('SRC_DEST', ('REG_OR_IMM, MEM_OR_REG',
                     'MEM, REG',
                     # Not allowed:
                     # MEM, MEM
                     # MEM, VALUE
                     ))

def Generate(instr):
  if len(instr) == 0:
    yield []
    return
  token = instr[0]
  if token in prods:
    vals = (x for toks in prods[token]
            for x in Generate(toks))
  else:
    vals = [[token]]
  for val in vals:
    for rest in Generate(instr[1:]):
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
  'pushl MEM_OR_REG',
  'pushl $VALUE',
  'popl MEM_OR_REG',
  'addl SRC_DEST',
  'subl SRC_DEST',
  'andl SRC_DEST',
  'orl SRC_DEST',
  'xorl SRC_DEST',
  'cmpl SRC_DEST',
  'testl SRC_DEST',
  'negl MEM_OR_REG',
  'notl MEM_OR_REG',
  'incl MEM_OR_REG',
  'decl MEM_OR_REG',
  'movl SRC_DEST',
  'lea MEM, REG', # includes pointless 'lea (%eax), %eax'
  ]


def FormatBytes(bytes):
  return ' '.join(FormatByte(byte) for byte in bytes)


fh = open('patterns', 'w')
for template in templates:
  for instr in Generate(list(Tokenise(template))):
    bytes = TryInstr(instr)
    instr_str = ''.join(instr)
    fh.write('%s:%s\n' % (FormatBytes(bytes), instr_str))
    print '%s    %s' % (instr_str, FormatBytes(bytes))
fh.close()
