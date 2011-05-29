
import re

import objdump


def ByteToRegexp(byte):
  if byte == 'XX':
    return '.'
  else:
    return re.escape(chr(int(byte, 16)))

def BytesToRegexp(bytes):
  return ''.join(ByteToRegexp(byte) for byte in bytes)


terms = []
for line in open('patterns'):
  terms.append(BytesToRegexp(line.split(':', 1)[0].split(' ')))

regexp = re.compile('|'.join(terms) + '$', re.DOTALL)


def Format(string):
  return ' '.join('%02x' % ord(byte) for byte in string)

for bytes, disasm in objdump.Decode('runnable-ld.so'):
  ok = regexp.match(bytes) is not None
  print ok, disasm, Format(bytes)
