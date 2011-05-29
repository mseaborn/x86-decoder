
import objdump


info = eval(open('trie_data', 'r').read(), {})


def CheckInstr(bytes):
  node = info['start']
  for byte in bytes:
    if 'XX' in info['map'][node]:
      node = info['map'][node]['XX']
    elif byte in info['map'][node]:
      node = info['map'][node][byte]
    else:
      return False
  return info['accepts'][node]


def Format(string):
  return ' '.join('%02x' % ord(byte) for byte in string)

for bytes, disasm in objdump.Decode('runnable-ld.so'):
  ok = CheckInstr(['%02x' % ord(byte) for byte in bytes])
  if disasm.startswith('j') or 'call' in disasm:
    ok = 'Jump'
  print ok, disasm, Format(bytes)
