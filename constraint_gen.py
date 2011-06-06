
import sys

import objdump_check

from logic import (Equal, EqualVar, NotEqual, Apply, ForRange,
                   Conj, Disj, Switch,
                   GenerateAll, GetAll,
                   assert_eq)


def IfEqual(var, x, then_clause, else_clause):
  return Disj(Conj(Equal(var, x), then_clause),
              Conj(NotEqual(var, x), else_clause))

def IfEqual2(var1, x1, var2, x2, then_clause, else_clause):
  # This is better than writing the more symmetrical code:
  #   Disj(Conj(Equal(var1, x1),
  #             Equal(var2, x2),
  #             then_clause),
  #        Conj(NotEqual(var1, x1), else_clause), 
  #        Conj(NotEqual(var2, x2), else_clause))
  # because if var1 != x1 and var2 != x2, both of those last clauses
  # in the disjunction will fire, causing duplicate results.
  return IfEqual(var1, x1,
                 IfEqual(var2, x2, then_clause, else_clause),
                 else_clause)

# This could be optimised to create fewer choice points.
def Mapping(var1, var2, pairs):
  return Disj(*[Conj(Equal(var1, x1),
                     Equal(var2, x2))
                for x1, x2 in pairs])

def Mapping3(var1, var2, var3, pairs):
  return Disj(*[Conj(Equal(var1, x1),
                     Equal(var2, x2),
                     Equal(var3, x3))
                for x1, x2, x3 in pairs])


def CatBits(values, sizes_in_bits):
  result = 0
  for value, size_in_bits in zip(values, sizes_in_bits):
    assert isinstance(value, int)
    assert 0 <= value
    assert value < (1 << size_in_bits)
    result = (result << size_in_bits) | value
  return result

def CatBitsRev(value, sizes_in_bits):
  parts = []
  for size_in_bits in reversed(sizes_in_bits):
    parts.insert(0, value & ((1 << size_in_bits) - 1))
    value >>= size_in_bits
  assert_eq(value, 0)
  return tuple(parts)
CatBits.rev = CatBitsRev

reg_count = 8

regs32 = (
  '%eax',
  '%ecx',
  '%edx',
  '%ebx',
  '%esp',
  '%ebp',
  '%esi',
  '%edi')

def RegName(args):
  return regs32[args[0]]

def ScaleVal(args):
  return 1 << args[0]

def PrependByte(args):
  byte, bytes = args
  return ['%02x' % byte] + bytes
def PrependByteRev(bytes):
  if len(bytes) == 0:
    return None
  return (int(bytes[0], 16), bytes[1:])
PrependByte.rev = PrependByteRev

def PrependWildcard(args):
  size, bytes = args
  return ['XX'] * size + bytes

def Format(args, format):
  return format % tuple(args)


def CheckReversing(func, args, *extra):
  assert_eq(func.rev(func(args, *extra), *extra), tuple(args))

CheckReversing(PrependByte, [0x12, ['XX', 'XX']])
CheckReversing(CatBits, [3, 4, 5], [2, 3, 3])


SibEncoding = Conj(
    ForRange('scale', 4),
    ForRange('indexreg', reg_count),
    ForRange('basereg', reg_count),
    # %ebp (register 5) is not accepted with a 0-byte displacement.
    # %ebp can only be used with a 1-byte or 4-byte displacement.
    IfEqual2('basereg', 5,
             'mod', 0,
             Equal('basereg_name', ''),
             Apply('basereg_name', RegName, ['basereg'])),
    Apply('scale_val', ScaleVal, ['scale']),
    # %esp is not accepted in the position '(reg, %esp)'.
    # In this context, register 4 is %eiz (an always-zero value).
    Disj(Conj(NotEqual('indexreg', 4),
              Apply('indexreg_name', RegName, ['indexreg']),
              Equal('mention_index', 1),
              ),
         # The only situation in which it really makes sense to use
         # %eiz is when basereg is %esp (register 4).  In that case,
         # we hide it in the decoding, unless the encoding is
         # non-canonical.
         Conj(Equal('indexreg', 4),
              Equal('indexreg_name', '%eiz'),
              IfEqual2('basereg', 4, # %esp
                       'scale', 0,
                       Equal('mention_index', 0),
                       Equal('mention_index', 1)),
              )),
    Switch('mention_index',
           (1, Apply('sib_arg', Format,
                     ['basereg_name', 'indexreg_name', 'scale_val'],
                     '(%s, %s, %i)')),
           (0, Apply('sib_arg', Format, ['basereg_name'], '(%s)'))),
    Apply('sib_byte', CatBits, ['scale', 'indexreg', 'basereg'], [2,3,3]),
    )

# rm argument is a register.
ModRMRegister = Conj(
    ForRange('reg2', reg_count),
    Apply('rm_arg', RegName, ['reg2']),
    Equal('mod', 3),
    Equal('has_sib_byte', 0),
    Equal('displacement_bytes', 0),
    )
# rm argument is an absolute address with no base/index reg.
ModRMAbsoluteAddr = Conj(
    Equal('mod', 0),
    Equal('reg2', 5),
    Equal('has_sib_byte', 0),
    Equal('displacement_bytes', 4),
    Equal('rm_arg', 'VALUE32'),
    )
# rm argument is of the form DISP(%reg).
ModRMDisp = Conj(
    ForRange('reg2', reg_count),
    # %esp (register 4) is not accepted in this position.
    # 4 is a special value: it adds a SIB byte.
    NotEqual('reg2', 4),
    Apply('indexreg_name', RegName, ['reg2']),
    Equal('has_sib_byte', 0),
    Disj(Conj(Equal('mod', 2),
              Equal('displacement_bytes', 4),
              Apply('rm_arg', Format, ['indexreg_name'], 'VALUE32(%s)'),
              ),
         Conj(Equal('mod', 1),
              Equal('displacement_bytes', 1),
              Apply('rm_arg', Format, ['indexreg_name'], 'VALUE8(%s)'),
              ),
         Conj(Equal('mod', 0),
              Equal('displacement_bytes', 0),
              Apply('rm_arg', Format, ['indexreg_name'], '(%s)'),
              # %ebp (register 5) is not accepted in this position,
              # because this encoding is used for ModRMAbsoluteAddr.
              # Using %ebp as a base register requires encoding it
              # with a SIB byte.
              NotEqual('reg2', 5),
              )))
# rm argument is of the form DISP(%reg, %reg, SCALE)
ModRMSib = Conj(
    Equal('reg2', 4), # Indicates that a SIB byte follows.
    ForRange('mod', 3),
    Equal('has_sib_byte', 1),
    SibEncoding,
    Disj(Conj(Equal('mod', 2),
              Equal('displacement_bytes', 4),
              Apply('rm_arg', Format, ['sib_arg'], 'VALUE32%s'),
              ),
         Conj(Equal('mod', 1),
              Equal('displacement_bytes', 1),
              Apply('rm_arg', Format, ['sib_arg'], 'VALUE8%s'),
              ),
         Conj(Equal('mod', 0),
              # %ebp (register 5) is treated specially.
              Disj(Conj(Equal('basereg', 5),
                        Equal('displacement_bytes', 4),
                        Apply('rm_arg', Format, ['sib_arg'], 'VALUE32%s')),
                   Conj(NotEqual('basereg', 5),
                        Equal('displacement_bytes', 0),
                        Apply('rm_arg', Format, ['sib_arg'], '%s')))),
         ))
ModRM = Conj(Apply('modrm_byte', CatBits, ['mod', 'reg1', 'reg2'], [2,3,3]),
             Equal('has_modrm_byte', 1),
             Disj(ModRMRegister,
                  ModRMAbsoluteAddr,
                  ModRMDisp,
                  ModRMSib,
                  ),
             )
ModRMDoubleArg = Conj(Equal('has_modrm_opcode', 0),
                      ForRange('reg1', reg_count),
                      Apply('reg1_name', RegName, ['reg1']),
                      ModRM)
ModRMSingleArg = Conj(Equal('has_modrm_opcode', 1),
                      EqualVar('reg1', 'modrm_opcode'),
                      ModRM)

NoModRM = Conj(
    Equal('has_modrm_byte', 0),
    Equal('has_modrm_opcode', 0),
    Equal('has_sib_byte', 0),
    Equal('displacement_bytes', 0))

Format_reg_rm = Conj(
    Equal('immediate_bytes', 0),
    ModRMDoubleArg,
    Apply('args', Format, ['reg1_name', 'rm_arg'], '%s, %s'))
Format_rm_reg = Conj(
    Equal('immediate_bytes', 0),
    ModRMDoubleArg,
    Apply('args', Format, ['rm_arg', 'reg1_name'], '%s, %s'))
Format_imm_rm = Conj(
    Equal('immediate_bytes', 4),
    ModRMSingleArg,
    Apply('args', Format, ['rm_arg'], '$VALUE32, %s'))
Format_imm8_rm = Conj(
    Equal('immediate_bytes', 1),
    ModRMSingleArg,
    Apply('args', Format, ['rm_arg'], '$VALUE8, %s'))
Format_imm_rm_reg = Conj(
    Equal('immediate_bytes', 4),
    ModRMDoubleArg,
    Apply('args', Format, ['rm_arg', 'reg1_name'], '$VALUE32, %s, %s'))
Format_imm8_rm_reg = Conj(
    Equal('immediate_bytes', 1),
    ModRMDoubleArg,
    Apply('args', Format, ['rm_arg', 'reg1_name'], '$VALUE8, %s, %s'))
Format_rm = Conj(
    Equal('immediate_bytes', 0),
    ModRMSingleArg,
    EqualVar('args', 'rm_arg'))
Format_imm_eax = Conj(
    NoModRM,
    Equal('immediate_bytes', 4),
    Equal('args', '$VALUE32, %eax'))
NoArguments = Conj(
    NoModRM,
    Equal('immediate_bytes', 0),
    Equal('args', ''))

# We use the condition names that objdump's disasembler produces here,
# although the alias names are more uniform.
ConditionCodes = Mapping(
    'cond', 'cond_name',
    [(0, 'o'),
     (1, 'no'),
     (2, 'b'),
     (3, 'ae'), # nb
     (4, 'e'), # z
     (5, 'ne'), # nz
     (6, 'be'),
     (7, 'a'), # nbe
     (8, 's'),
     (9, 'ns'),
     (10, 'p'),
     (11, 'np'),
     (12, 'l'),
     (13, 'ge'), # nl
     (14, 'le'),
     (15, 'g'), # nle
     ])

ArithOpcodes = Conj(
    Disj(Conj(Apply('opcode', CatBits,
                    ['arith_opcode', 'arith_opcode_bottom'], [5, 3]),
              Disj(Conj(Equal('arith_opcode_bottom', 1), Format_reg_rm),
                   Conj(Equal('arith_opcode_bottom', 3), Format_rm_reg),
                   Conj(Equal('arith_opcode_bottom', 5), Format_imm_eax),
                   )),
         Conj(Equal('opcode', 0x81),
              EqualVar('modrm_opcode', 'arith_opcode'),
              Format_imm_rm),
         Conj(Equal('opcode', 0x83),
              EqualVar('modrm_opcode', 'arith_opcode'),
              Format_imm8_rm),
         ),
    Switch('arith_opcode',
           (0, Equal('inst', 'addl')),
           (1, Equal('inst', 'orl')),
           (2, Equal('inst', 'adcl')),
           (3, Equal('inst', 'sbbl')),
           (4, Equal('inst', 'andl')),
           (5, Equal('inst', 'subl')),
           (6, Equal('inst', 'xorl')),
           (7, Equal('inst', 'cmpl')),
           ))

OneByteOpcodes = Disj(
    Conj(Equal('inst', 'movl'), Equal('opcode', 0x89), Format_reg_rm),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0x8b), Format_rm_reg),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0xc7),
         Equal('modrm_opcode', 0), Format_imm_rm),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0xa1),
         NoModRM,
         Equal('immediate_bytes', 4),
         Equal('args', 'VALUE32, %eax')),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0xa3),
         NoModRM,
         Equal('immediate_bytes', 4),
         Equal('args', '%eax, VALUE32')),
    Conj(Equal('inst', 'movl'),
         ForRange('reg1', reg_count),
         Apply('reg1_name', RegName, ['reg1']),
         Equal('opcode_top', 0xb8 >> 3),
         Apply('opcode', CatBits, ['opcode_top', 'reg1'], (5, 3)),
         NoModRM,
         Equal('immediate_bytes', 4),
         Apply('args', Format, ['reg1_name'], '$VALUE32, %s')),

    ArithOpcodes,

    Conj(Disj(Conj(Equal('inst', 'incl'),  Equal('opcode_top', 0x40 >> 3)),
              Conj(Equal('inst', 'decl'),  Equal('opcode_top', 0x48 >> 3)),
              Conj(Equal('inst', 'pushl'), Equal('opcode_top', 0x50 >> 3)),
              Conj(Equal('inst', 'popl'),  Equal('opcode_top', 0x58 >> 3)),
              ),
         ForRange('reg', reg_count),
         Apply('reg_name', RegName, ['reg']),
         Apply('opcode', CatBits, ['opcode_top', 'reg'], (5, 3)),
         NoModRM,
         Equal('immediate_bytes', 0),
         EqualVar('args', 'reg_name')),

    Conj(Equal('inst', 'pushl'),
         Equal('opcode', 0x68),
         NoModRM,
         Equal('immediate_bytes', 4),
         Equal('args', '$VALUE32')),
    Conj(Equal('inst', 'pushl'),
         Equal('opcode', 0x6a),
         NoModRM,
         Equal('immediate_bytes', 1),
         Equal('args', '$VALUE8')),

    Conj(Equal('inst', 'imull'), Equal('opcode', 0x69), Format_imm_rm_reg),
    Conj(Equal('inst', 'imull'), Equal('opcode', 0x6b), Format_imm8_rm_reg),

    # Short (8-bit offset) jumps
    Conj(Equal('opcode_top', 0x70 >> 4),
         Apply('opcode', CatBits, ['opcode_top', 'cond'], [4, 4]),
         ConditionCodes,
         NoModRM,
         Equal('immediate_bytes', 1),
         Equal('args', 'JUMP_DEST'),
         Apply('inst', Format, ['cond_name'], 'j%s')),

    Conj(Equal('inst', 'testl'), Equal('opcode', 0x85), Format_reg_rm),
    Conj(Equal('inst', 'xchgl'), Equal('opcode', 0x87), Format_reg_rm),
    Conj(Equal('inst', 'leal'),
         Equal('opcode', 0x8d),
         Format_rm_reg,
         # Disallow instructions of the form 'leal %reg, %reg'.
         # We require a modrm byte that looks like a memory access,
         # though the instruction does not perform a memory access.
         NotEqual('mod', 3)),
    Conj(Equal('inst', 'popl'),
         Equal('opcode', 0x8f),
         Equal('modrm_opcode', 0),
         Format_rm),

    Conj(Equal('inst', 'nop'), Equal('opcode', 0x90), NoArguments),
    # 'xchg %eax, %reg'
    Conj(Equal('inst', 'xchgl'),
         ForRange('reg1', reg_count),
         # 'xchg %eax, %eax' (0x90) is disassembled as 'nop'.
         # On x86-64, it really is a no-op and does not clear the top
         # bits of %rax.
         NotEqual('reg1', 0), # %eax
         Apply('reg1_name', RegName, ['reg1']),
         Equal('opcode_top', 0x90 >> 3),
         Apply('opcode', CatBits, ['opcode_top', 'reg1'], (5, 3)),
         NoModRM,
         Equal('immediate_bytes', 0),
         Apply('args', Format, ['reg1_name'], '%%eax, %s')),

    # 'cwtl' is also known as 'cbw'/'cwde' in Intel syntax.
    Conj(Equal('inst', 'cwtl'), Equal('opcode', 0x98), NoArguments),
    # 'cltd' is also known as 'cwd'/'cdq' in Intel syntax.
    Conj(Equal('inst', 'cltd'), Equal('opcode', 0x99), NoArguments),

    Conj(Equal('inst', 'calll'),
         Equal('opcode', 0xe8),
         NoModRM,
         Equal('immediate_bytes', 4),
         Equal('args', 'JUMP_DEST')),

    # String operations.
    Conj(Mapping3('inst', 'opcode', 'args',
                  [('movsb', 0xa4, '%ds:(%esi), %es:(%edi)'),
                   ('movsl', 0xa5, '%ds:(%esi), %es:(%edi)'),
                   ('cmpsb', 0xa6, '%es:(%edi), %ds:(%esi)'),
                   ('cmpsl', 0xa7, '%es:(%edi), %ds:(%esi)'),
                   ('stosb', 0xaa, '%al, %es:(%edi)'),
                   ('stosl', 0xab, '%eax, %es:(%edi)'),
                   ('lodsb', 0xac, '%ds:(%esi), %al'),
                   ('lodsl', 0xad, '%ds:(%esi), %eax'),
                   ('scasb', 0xae, '%es:(%edi), %al'),
                   ('scasl', 0xaf, '%es:(%edi), %eax'),
                   ]),
         NoModRM,
         Equal('immediate_bytes', 0)),

    Conj(Equal('inst', 'testl'), Equal('opcode', 0xa9), Format_imm_eax),
    )

TwoByteOpcodes = Disj(
    Conj(Equal('opcode', 0x0f),
         Equal('opcode2_top', 0x80 >> 4),
         Apply('opcode2', CatBits, ['opcode2_top', 'cond'], [4, 4]),
         ConditionCodes,
         NoModRM,
         Equal('immediate_bytes', 4),
         Equal('args', 'JUMP_DEST'),
         Apply('inst', Format, ['cond_name'], 'j%s')),
    )

ConcatBytes = Conj(
    Apply('bytes', PrependByte, ['opcode', 'bytes1']),
    Switch('has_opcode2',
           (1, Apply('bytes1', PrependByte, ['opcode2', 'bytes2'])),
           (0, EqualVar('bytes1', 'bytes2'))),
    Switch('has_modrm_byte',
           (1, Apply('bytes2', PrependByte, ['modrm_byte', 'bytes3'])),
           (0, EqualVar('bytes2', 'bytes3'))),
    Switch('has_sib_byte',
           (1, Apply('bytes3', PrependByte, ['sib_byte', 'bytes4'])),
           (0, EqualVar('bytes3', 'bytes4'))),
    Apply('bytes4', PrependWildcard, ['displacement_bytes', 'bytes5']),
    Apply('bytes5', PrependWildcard, ['immediate_bytes', 'bytes6']),
    Equal('bytes6', []))

# We call ConcatBytes after setting has_opcode2 to reduce the
# expanding-out of combinations that ConcatBytes does.
Instructions = Disj(
    Conj(Equal('has_opcode2', 0), ConcatBytes, OneByteOpcodes),
    Conj(Equal('has_opcode2', 1), ConcatBytes, TwoByteOpcodes),
    )

Encode = Conj(
    Instructions,
    Apply('desc', Format, ['inst', 'args'], '%s %s'))


# Test decoding an instruction.
def TestInstruction(bytes, desc):
  decoded = GetAll(Conj(Equal('bytes', bytes.split(' ')), Encode))
  assert_eq([info['desc'] for info in decoded],
            [desc])

TestInstruction('90', 'nop ')
TestInstruction('89 04 f4', 'movl %eax, (%esp, %esi, 8)')
# This used to generate the output twice because of an awkward
# negation construct.
TestInstruction('89 04 60', 'movl %eax, (%eax, %eiz, 2)')


def TestObjdump(clause):
  bits = 32
  instrs = []
  GenerateAll(clause,
              lambda info: instrs.append((info['bytes'], info['desc'])))
  objdump_check.DisassembleTest(lambda: instrs, bits)

  # Check that there are no duplicates.
  instrs = [(' '.join(bytes), desc) for bytes, desc in instrs]
  assert_eq(len(instrs), len(set(instrs)))
  return instrs

# Generate one example of each type of instruction.
# We do this by preventing all values of modrm_byte from being enumerated.
OneOfEachType = Disj(
    Conj(Equal('has_modrm_opcode', 0),
         Equal('modrm_byte', 0),
         Encode),
    Conj(Equal('has_modrm_opcode', 1),
         Equal('mod', 0),
         Equal('reg2', 0),
         Encode))

GenerateAll(OneOfEachType,
            lambda info: sys.stdout.write(
                '%s:%s\n' % (' '.join(info['bytes']), info['desc'])))
TestObjdump(OneOfEachType)

# Check all modrm/sib byte values.
movs = TestObjdump(Conj(Equal('opcode', 0x89), Equal('sib_byte', 0), Encode))
assert_eq(len(movs), 256)
movs = TestObjdump(Conj(Equal('opcode', 0x89), Equal('modrm_byte', 4), Encode))
assert_eq(len(movs), 256)
movs = TestObjdump(Conj(Equal('opcode', 0x89), Encode))
# There are 6376 combinations of modrm/sib bytes.
# There are 3*8 = 24 modrm bytes that indicate a sib byte follows.
# There are 256 - 24 = 232 modrm bytes without sib bytes.
# There are 256 * 24 = 6144 combinations of modrm bytes and sib bytes.
assert_eq(len(movs), 232 + 6144)

# 'lea' is special since it uses modrm but does not access memory.
# This means 'leal %eax, %eax' is not valid.  Check that we exclude it.
# We do not exclude redundant forms such as 'leal (%ebx), %eax'
# (which is equivalent to 'movl %ebx, %eax').
leas = TestObjdump(Conj(Equal('inst', 'leal'), Encode))
# Subtract the number of modrm byte values that are excluded.
assert_eq(len(leas), 6376 - 64)

# Test all instructions.  This is slower.
TestObjdump(Encode)
