# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import subprocess


def WriteFile(filename, data):
  fh = open(filename, "w")
  try:
    fh.write(data)
  finally:
    fh.close()


bits = 64

test_cases = []

def TestCase(asm, accept):
  def Func():
    print '* test %r' % asm
    full_asm = asm + '\n.p2align 5, 0x90\n'
    WriteFile('tmp.S', full_asm)
    subprocess.check_call(['gcc', '-m%i' % bits, '-c', 'tmp.S', '-o', 'tmp.o'])
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
mov $0x12345678, %rax
mov $0x1234567812345678, %rax
""")

# Check a disallowed instruction.
TestCase(accept=False, asm="""
nop
int $0x80
""")

TestCase(accept=False, asm='ret')

TestCase(accept=False, asm='syscall')

# Instruction bundle overflow.
TestCase(accept=False, asm="""
mov $0x1234567812345678, %rax
mov $0x1234567812345678, %rax
mov $0x1234567812345678, %rax
mov $0x1234567812345678, %rax
""")

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
mov $0x1234567812345678, %rax
jmp label + 1
""")


# Unmasked indirect jumps are disallowed.
TestCase(accept=False, asm='jmp *%rax')
TestCase(accept=False, asm='jmp *(%rax)')
TestCase(accept=False, asm='call *%rax')
TestCase(accept=False, asm='call *(%rax)')

# Masking instructions on their own are allowed.
TestCase(accept=True, asm='and $~31, %eax')
TestCase(accept=True, asm='and $~31, %ebx')
TestCase(accept=True, asm='and $~31, %rax')
TestCase(accept=True, asm='and $~31, %rbx')
# TODO: This should be accepted.
TestCase(accept=False, asm='and $~31, %eax; add %r15, %rax')
TestCase(accept=False, asm='and $~31, %ebx; add %r15, %rbx')

# Masked indirect jumps are allowed.
TestCase(accept=True, asm='and $~31, %eax; add %r15, %rax; jmp *%rax')
TestCase(accept=True, asm='and $~31, %ebx; add %r15, %rbx; call *%rbx')

# The registers must match up for the mask and the jump.
TestCase(accept=False, asm='and $~31, %ebx; add %r15, %rax; jmp *%rax')
TestCase(accept=False, asm='and $~31, %eax; add %r15, %rbx; jmp *%rax')
TestCase(accept=False, asm='and $~31, %eax; add %r15, %rax; jmp *%rbx')
TestCase(accept=False, asm='and $~31, %eax; add %r15, %rbx; jmp *%rbx')
TestCase(accept=False, asm='and $~31, %ebx; add %r15, %rbx; jmp *%rax')

# The mask and the jump must be adjacent.
TestCase(accept=False, asm='and $~31, %eax; nop; add %r15, %rax; jmp *%rax')
TestCase(accept=False, asm='and $~31, %eax; add %r15, %rax; nop; jmp *%rax')

# Jumping into the middle of the superinstruction must be rejected.
TestCase(accept=False, asm="""
and $~31, %eax
add %r15, %rax
label:
jmp *%rax
jmp label
""")
TestCase(accept=False, asm="""
and $~31, %eax
label:
add %r15, %rax
jmp *%rax
jmp label
""")


def Main():
  for test_case in test_cases:
    test_case()
  print 'PASS'


if __name__ == '__main__':
  Main()
