
import re
import subprocess


def write_file(filename, data):
  fh = open(filename, "w")
  try:
    fh.write(data)
  finally:
    fh.close()


def Encode(instr):
  write_file('tmp.S', instr + '\n')
  subprocess.check_call(['as', '--32', 'tmp.S', '-o', 'tmp.o'])
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
  assert len(both) == 1
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
  regexp = re.compile('[A-Z]+')
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

def Generate(instr):
  if len(instr) == 0:
    yield []
    return
  if instr[0] == 'REG':
    vals = regs
  else:
    vals = [instr[0]]
  for val in vals:
    for rest in Generate(instr[1:]):
      yield [val] + rest


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
  'add $VALUE, REG',
  'sub $VALUE, REG',
  'and $VALUE, REG',
  'or $VALUE, REG',
  'movl REG, REG',
  'movl $VALUE, (REG)',
  'movl REG, (REG)',
  'movl (REG), REG',
  'movl $VALUE, VALUE(REG)',
  ]


for template in templates:
  for instr in Generate(list(Tokenise(template))):
    bytes = TryInstr(instr)
    print '%s    %s' % (''.join(instr),
                        ' '.join(FormatByte(byte) for byte in bytes))
