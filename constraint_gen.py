
import sys

import objdump_check

from logic import (Equal, EqualVar, NotEqual, Apply, ForRange,
                   Conj, Disj, Switch,
                   GenerateAll, GetAll,
                   assert_eq)


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
    # Note: awkward negation construction.
    # %ebp (register 5) is not accepted with a 0-byte displacement.
    # %ebp can only be used with a 1-byte or 4-byte displacement.
    Disj(Conj(NotEqual('basereg', 5),
              Apply('basereg_name', RegName, ['basereg'])),
         Conj(NotEqual('mod', 0),
              Apply('basereg_name', RegName, ['basereg'])),
         Conj(Equal('basereg', 5),
              Equal('mod', 0),
              Equal('basereg_name', ''))),
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
              # Note: awkward negation construction.
              Disj(Conj(Equal('basereg', 4), # %esp
                        Equal('scale', 0),
                        Equal('mention_index', 0)),
                   # These are two non-canonical forms:
                   Conj(NotEqual('basereg', 4), # not %esp
                        Equal('mention_index', 1)),
                   Conj(NotEqual('scale', 0),
                        Equal('mention_index', 1))),
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
ModRMDoubleArg = Conj(ForRange('reg1', reg_count),
                      Apply('reg1_name', RegName, ['reg1']),
                      ModRM)
ModRMSingleArg = Conj(EqualVar('reg1', 'modrm_opcode'),
                      ModRM)

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

Mov = Disj(
    Conj(Equal('inst', 'movl'), Equal('opcode', 0x89), Format_reg_rm),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0x8b), Format_rm_reg),
    Conj(Equal('inst', 'movl'), Equal('opcode', 0xc7),
         Equal('modrm_opcode', 0), Format_imm_rm),
    Conj(Equal('inst', 'movl'),
         ForRange('reg1', reg_count),
         Apply('reg1_name', RegName, ['reg1']),
         Equal('opcode_top', 0xb8 >> 3),
         Apply('opcode', CatBits, ['opcode_top', 'reg1'], (5, 3)),
         Equal('has_modrm_byte', 0),
         Equal('has_sib_byte', 0),
         Equal('displacement_bytes', 0),
         Equal('immediate_bytes', 4),
         Apply('args', Format, ['reg1_name'], '$VALUE32, %s')),
    )

ConcatBytes = Conj(
    Apply('bytes', PrependByte, ['opcode', 'bytes1']),
    Switch('has_modrm_byte',
           (1, Apply('bytes1', PrependByte, ['modrm_byte', 'bytes2'])),
           (0, EqualVar('bytes1', 'bytes2'))),
    Switch('has_sib_byte',
           (1, Apply('bytes2', PrependByte, ['sib_byte', 'bytes3'])),
           (0, EqualVar('bytes2', 'bytes3'))),
    Apply('bytes3', PrependWildcard, ['displacement_bytes', 'bytes4']),
    Apply('bytes4', PrependWildcard, ['immediate_bytes', 'bytes5']),
    Equal('bytes5', []))

Encode = Conj(
    ConcatBytes,
    Mov,
    Apply('desc', Format, ['inst', 'args'], '%s %s'))


# Generate one example of each type of instruction.
# We do this by preventing all values of modrm_byte from being enumerated.
GenerateAll(Conj(Equal('modrm_byte', 0), Encode),
            lambda info: sys.stdout.write(
                '%s:%s\n' % (' '.join(info['bytes']), info['desc'])))

# Test decoding an instruction.
decoded = GetAll(Conj(Equal('bytes', '89 04 f4'.split(' ')),
                      Encode))
assert_eq([info['desc'] for info in decoded],
          ['movl %eax, (%esp, %esi, 8)'])


def GetAllEncodings():
  got = []
  GenerateAll(Encode, lambda info: got.append((info['bytes'], info['desc'])))
  return got

bits = 32
objdump_check.DisassembleTest(GetAllEncodings, bits)

GenerateAll(Encode,
            lambda info: sys.stdout.write(
                '%s:%s\n' % (' '.join(info['bytes']), info['desc'])))
