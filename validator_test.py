
import subprocess


def WriteFile(filename, data):
  fh = open(filename, "w")
  try:
    fh.write(data)
  finally:
    fh.close()


test_cases = []

def TestCase(asm, accept):
  def Func():
    print '* test'
    full_asm = asm + '\n.p2align 5, 0x90\n'
    WriteFile('tmp.S', full_asm)
    subprocess.check_call(['gcc', '-m32', '-c', 'tmp.S', '-o', 'tmp.o'])
    rc = subprocess.call(['./dfa_ncval', 'tmp.o'])
    if accept:
      assert rc == 0, rc
    else:
      assert rc == 1, rc
  test_cases.append(Func)


# Check some simple allowed instructions.
TestCase(accept=True, asm="""
nop
hlt
movl $0x12345678, 0x87654321(%eax, %ebx, 4)
""")

# Check a disallowed instruction.
TestCase(accept=False, asm="""
nop
int $0x80
""")

TestCase(accept=False, asm='ret')

# Instruction bundle overflow.
TestCase(accept=False, asm="""
movl $0x12345678, 0x12345678(%eax, %ebx, 4)
movl $0x12345678, 0x12345678(%eax, %ebx, 4)
movl $0x12345678, 0x12345678(%eax, %ebx, 4)
""")

# TODO: these should be rejected.
TestCase(accept=True, asm='jmp *%eax')
TestCase(accept=True, asm='jmp *(%eax)')
TestCase(accept=True, asm='call *%eax')
TestCase(accept=True, asm='call *(%eax)')

# Forwards and backwards jumps.
TestCase(accept=True, asm="""
nop
jmp label2
label1:
jmp label1
jmp label1
label2:
jmp label1
""")

# Out-of-range unaligned jump.
TestCase(accept=False, asm="""
label:
jmp label - 1
""")

# Out-of-range unaligned jump.
TestCase(accept=False, asm="""
jmp label + 1
.p2align 5
label:
""")

# Jump into instruction.
TestCase(accept=False, asm="""
label:
movl $0x12345678, 0x12345678(%eax, %ebx, 4)
jmp label + 1
""")


def Main():
  for test_case in test_cases:
    test_case()
  print 'PASS'


if __name__ == '__main__':
  Main()
