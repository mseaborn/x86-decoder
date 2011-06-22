
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


def Main():
  for test_case in test_cases:
    test_case()
  print 'PASS'


if __name__ == '__main__':
  Main()
