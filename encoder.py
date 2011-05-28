
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


db_file = 'cache.sqlite'
db_is_new = not os.path.exists(db_file)
db = sqlite3.connect(db_file)
if db_is_new:
  db.execute('create table encoding (instr, bytes)')
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


def DiscoverArg(instr_template):
  assert len(list(Matches(instr_template, 'VALUE'))) == 1

  def Try(value, value_str):
    bytes = Encode(instr_template.replace('VALUE', value))
    bytes_str = ''.join(bytes)
    return bytes, set(Matches(bytes_str, value_str))

  op_size = 4
  bytes1, indexes1 = Try('0x12345678', '\x78\x56\x34\x12')
  bytes2, indexes2 = Try('0x12345679', '\x79\x56\x34\x12')
  # op_size = 1
  # bytes1, indexes1 = Try('0x12', '\x12')
  # bytes2, indexes2 = Try('0x21', '\x21')
  both = indexes1.intersection(indexes2)
  assert_eq(len(both), 1)
  index = list(both)[0]

  def Erase(bytes):
    for i in range(index, index + op_size):
      bytes[i] = 'XX'
  Erase(bytes1)
  Erase(bytes2)
  assert bytes1 == bytes2
  return bytes1, index

assert_eq(DiscoverArg('and $VALUE, %ebx'),
          (['\x81', '\xe3', 'XX', 'XX', 'XX', 'XX'], 2))


def DiscoverArgs2(template):
  op_size = 4
  dummy = '0x11111111'
  # op_size = 1
  # dummy = '0x11'
  bytes1, index1 = DiscoverArg(template((dummy, 'VALUE')))
  bytes2, index2 = DiscoverArg(template(('VALUE', dummy)))

  def Erase(bytes, index):
    for i in range(index, index + op_size):
      assert bytes[i] == '\x11'
      bytes[i] = 'XX'
  Erase(bytes1, index2)
  Erase(bytes2, index1)
  assert bytes1 == bytes2
  return bytes1

assert_eq(DiscoverArgs2(lambda x: 'movl $%s, %s(%%ebx)' % x),
          ['\xc7', '\x83', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX', 'XX'])


def Tokenise(string):
  regexp = re.compile('[A-Z_]+')
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

AddProd('MEM', ('REG', '(REG)', 'VALUE(REG)',
                '(REG, REG_NOT_ESP)'
                ))
AddProd('MEM_ONLY', ('(REG)', 'VALUE(REG)'))
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
  args = 0
  for token in instr:
    if token == 'VALUE':
      args += 1
  if args == 0:
    return Encode(''.join(instr))
  elif args == 1:
    bytes, i = DiscoverArg(''.join(instr))
    return bytes
  else:
    indexes = [index for index, token in enumerate(instr)
               if token == 'VALUE']
    def Subst(vals):
      copy = instr[:]
      for i, val in zip(indexes, vals):
        copy[i] = val
      return ''.join(copy)
    return DiscoverArgs2(Subst)


templates = [
  'nop',
  'hlt',
  'pushl REG',
  'popl REG',
  'addl REG_OR_IMM, MEM',
  'subl REG_OR_IMM, MEM',
  'andl REG_OR_IMM, MEM',
  'orl REG_OR_IMM, MEM',
  'xorl REG_OR_IMM, MEM',
  'cmpl REG_OR_IMM, MEM',
  'testl REG_OR_IMM, MEM',
  'negl MEM',
  'notl MEM',
  'incl MEM',
  'decl MEM',
  # This produces overlaps with 'movl MEM, REG':
  # 'movl REG_OR_IMM, MEM',
  'movl $VALUE, MEM',
  'movl MEM, REG',
  'lea MEM_ONLY, REG', # includes pointless 'lea (%eax), %eax'
  ]


def FormatBytes(bytes):
  return ' '.join(FormatByte(byte) for byte in bytes)


fh = open('patterns', 'w')
for template in templates:
  for instr in Generate(list(Tokenise(template))):
    bytes = TryInstr(instr)
    fh.write(FormatBytes(bytes) + '\n')
    print '%s    %s' % (''.join(instr), FormatBytes(bytes))
fh.close()
