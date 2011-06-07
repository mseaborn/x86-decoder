
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

regs16 = (
  '%ax',
  '%cx',
  '%dx',
  '%bx',
  '%sp',
  '%bp',
  '%si',
  '%di')

regs8 = (
  '%al',
  '%cl',
  '%dl',
  '%bl',
  '%ah',
  '%ch',
  '%dh',
  '%bh')

def RegName(args):
  return regs32[args[0]]

def Reg16Name(args):
  return regs16[args[0]]

def Reg8Name(args):
  return regs8[args[0]]

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

def GetArgRegname(name_var, number_var):
  # The data16 prefix is not valid on byte operations.
  return Disj(Conj(Equal('has_data16_prefix', 0),
                   Equal('not_byte_op', 1),
                   Apply(name_var, RegName, [number_var])),
              Conj(Equal('has_data16_prefix', 1),
                   Equal('not_byte_op', 1),
                   Apply(name_var, Reg16Name, [number_var])),
              Conj(Equal('has_data16_prefix', 0),
                   Equal('not_byte_op', 0),
                   Apply(name_var, Reg8Name, [number_var])))

# For when %rax/%eax/%ax/%al is implicitly accessed.
GetAccArgRegname = Conj(
   Equal('acc_reg', 0),
   GetArgRegname('acc_regname', 'acc_reg'))

# rm argument is a register.
ModRMRegister = Conj(
    ForRange('reg2', reg_count),
    GetArgRegname('rm_arg', 'reg2'),
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
                        EqualVar('rm_arg', 'sib_arg')))),
         ))
ModRM = Conj(Apply('modrm_byte', CatBits, ['mod', 'reg1', 'reg2'], [2,3,3]),
             Equal('has_modrm_byte', 1),
             Equal('has_inst_suffix', 1),
             Disj(ModRMRegister,
                  ModRMAbsoluteAddr,
                  ModRMDisp,
                  ModRMSib,
                  ),
             )
ModRMDoubleArg = Conj(Equal('has_modrm_opcode', 0),
                      ForRange('reg1', reg_count),
                      GetArgRegname('reg1_name', 'reg1'),
                      ModRM)
ModRMSingleArg = Conj(Equal('has_modrm_opcode', 1),
                      EqualVar('reg1', 'modrm_opcode'),
                      ModRM)

NoModRM = Conj(
    Equal('has_modrm_byte', 0),
    Equal('has_modrm_opcode', 0),
    Equal('has_sib_byte', 0),
    Equal('displacement_bytes', 0))

DataOperationWithoutModRM = Conj(
    NoModRM,
    Equal('has_inst_suffix', 1))

# This is for jumps that do no data operation, so it does not make
# sense to add a 'l' or 'w' suffix or use a data16 prefix.
NoDataOperation = Conj(
    NoModRM,
    Equal('has_data16_prefix', 0),
    Equal('has_inst_suffix', 0))

DefaultImmediateSize = \
    Switch('has_data16_prefix',
           (1, Conj(Equal('immediate_bytes', 2),
                    Equal('immediate_desc', '$VALUE16'))),
           (0, Switch('not_byte_op',
                      (0, Conj(Equal('immediate_bytes', 1),
                               Equal('immediate_desc', '$VALUE8'))),
                      (1, Conj(Equal('immediate_bytes', 4),
                               Equal('immediate_desc', '$VALUE32'))))))

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
    DefaultImmediateSize,
    Apply('args', Format, ['immediate_desc', 'rm_arg'], '%s, %s'))
Format_imm8_rm = Conj(
    Equal('immediate_bytes', 1),
    ModRMSingleArg,
    Apply('args', Format, ['rm_arg'], '$VALUE8, %s'))
Format_imm_rm_reg = Conj(
    Equal('immediate_bytes', 4),
    ModRMDoubleArg,
    DefaultImmediateSize,
    Apply('args', Format, ['immediate_desc', 'rm_arg', 'reg1_name'],
          '%s, %s, %s'))
Format_imm8_rm_reg = Conj(
    Equal('immediate_bytes', 1),
    ModRMDoubleArg,
    Apply('args', Format, ['rm_arg', 'reg1_name'], '$VALUE8, %s, %s'))
Format_rm = Conj(
    Equal('immediate_bytes', 0),
    ModRMSingleArg,
    EqualVar('args', 'rm_arg'))
Format_imm_eax = Conj(
    DataOperationWithoutModRM,
    DefaultImmediateSize,
    GetAccArgRegname,
    Apply('args', Format, ['immediate_desc', 'acc_regname'], '%s, %s'))

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

# Many opcodes come in pairs: X is the 8-bit version, and X+1 is the
# 32-bit version which can be made into 16-bit with the data16 prefix.
def OpcodePair(opcode_base):
  # This could be done with CatBits but it's not really worth it.
  return Mapping('opcode', 'not_byte_op',
                 [(opcode_base, 0),
                  (opcode_base + 1, 1)])

# Opcodes that work with 'l' (32-bit) or 'w' (16-bit) suffixes.
def OpcodeLW(opcode_byte):
  return Conj(Equal('opcode', opcode_byte),
              Equal('not_byte_op', 1))

ArithOpcodes = Conj(
    Disj(Conj(Apply('opcode', CatBits,
                    ['arith_opcode', 'arith_opcode_format', 'not_byte_op'],
                    [5, 2, 1]),
              Disj(Conj(Equal('arith_opcode_format', 0), Format_reg_rm),
                   Conj(Equal('arith_opcode_format', 1), Format_rm_reg),
                   Conj(Equal('arith_opcode_format', 2), Format_imm_eax),
                   )),
         Conj(OpcodePair(0x80),
              EqualVar('modrm_opcode', 'arith_opcode'),
              Format_imm_rm),
         # 0x82 is a hole in the table.  We don't use OpcodePair(0x82)
         # here because 0x80 and 0x82 would be equivalent (both 8-bit
         # ops with imm8).
         Conj(OpcodeLW(0x83),
              EqualVar('modrm_opcode', 'arith_opcode'),
              Format_imm8_rm),
         ),
    Switch('arith_opcode',
           (0, Equal('inst', 'add')),
           (1, Equal('inst', 'or')),
           (2, Equal('inst', 'adc')),
           (3, Equal('inst', 'sbb')),
           (4, Equal('inst', 'and')),
           (5, Equal('inst', 'sub')),
           (6, Equal('inst', 'xor')),
           (7, Equal('inst', 'cmp')),
           ))

OneByteOpcodes = Disj(
    Conj(Equal('inst', 'mov'), OpcodePair(0x88), Format_reg_rm),
    Conj(Equal('inst', 'mov'), OpcodePair(0x8a), Format_rm_reg),
    Conj(Equal('inst', 'mov'), OpcodePair(0xc6),
         Equal('modrm_opcode', 0), Format_imm_rm),
    Conj(Equal('inst', 'mov'), OpcodePair(0xa0),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 4),
         GetAccArgRegname,
         Apply('args', Format, ['acc_regname'], 'VALUE32, %s')),
    Conj(Equal('inst', 'mov'), OpcodePair(0xa2),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 4),
         GetAccArgRegname,
         Apply('args', Format, ['acc_regname'], '%s, VALUE32')),
    Conj(Equal('inst', 'mov'),
         ForRange('reg1', reg_count),
         GetArgRegname('reg1_name', 'reg1'),
         Equal('opcode_top', 0xb0 >> 4),
         Apply('opcode', CatBits, ['opcode_top', 'not_byte_op', 'reg1'],
               (4, 1, 3)),
         DataOperationWithoutModRM,
         DefaultImmediateSize,
         Apply('args', Format, ['immediate_desc', 'reg1_name'], '%s, %s')),

    ArithOpcodes,

    Conj(Disj(Conj(Equal('inst', 'inc'),  Equal('opcode_top', 0x40 >> 3)),
              Conj(Equal('inst', 'dec'),  Equal('opcode_top', 0x48 >> 3)),
              Conj(Equal('inst', 'push'), Equal('opcode_top', 0x50 >> 3)),
              Conj(Equal('inst', 'pop'),  Equal('opcode_top', 0x58 >> 3)),
              ),
         ForRange('reg', reg_count),
         GetArgRegname('reg_name', 'reg'),
         Apply('opcode', CatBits, ['opcode_top', 'reg'], (5, 3)),
         Equal('not_byte_op', 1),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 0),
         EqualVar('args', 'reg_name')),

    Conj(Equal('inst', 'push'),
         OpcodeLW(0x68),
         DataOperationWithoutModRM,
         DefaultImmediateSize,
         EqualVar('args', 'immediate_desc')),
    Conj(Equal('inst', 'push'),
         OpcodeLW(0x6a),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 1),
         Equal('args', '$VALUE8')),

    Conj(Equal('inst', 'imul'), OpcodeLW(0x69), Format_imm_rm_reg),
    Conj(Equal('inst', 'imul'), OpcodeLW(0x6b), Format_imm8_rm_reg),

    # Short (8-bit offset) jumps
    Conj(Equal('opcode_top', 0x70 >> 4),
         Apply('opcode', CatBits, ['opcode_top', 'cond'], [4, 4]),
         ConditionCodes,
         NoDataOperation,
         Equal('immediate_bytes', 1),
         Equal('args', 'JUMP_DEST'),
         Apply('inst', Format, ['cond_name'], 'j%s')),

    Conj(Equal('inst', 'test'), OpcodePair(0x84), Format_reg_rm),
    Conj(Equal('inst', 'xchg'), OpcodePair(0x86), Format_reg_rm),
    Conj(Equal('inst', 'lea'),
         OpcodeLW(0x8d),
         Format_rm_reg,
         # Disallow instructions of the form 'leal %reg, %reg'.
         # We require a modrm byte that looks like a memory access,
         # though the instruction does not perform a memory access.
         NotEqual('mod', 3)),
    Conj(Equal('inst', 'pop'),
         OpcodeLW(0x8f),
         Equal('modrm_opcode', 0),
         Format_rm),

    Conj(Equal('inst', 'nop'),
         Equal('opcode', 0x90),
         NoModRM,
         Equal('has_inst_suffix', 0),
         Equal('has_data16_prefix', 0),
         Equal('immediate_bytes', 0),
         Equal('args', '')),
    # 'xchg %eax, %reg'
    Conj(Equal('inst', 'xchg'),
         ForRange('reg1', reg_count),
         # 'xchg %eax, %eax' (0x90) is disassembled as 'nop'.
         # On x86-64, it really is a no-op and does not clear the top
         # bits of %rax.
         NotEqual('reg1', 0), # %eax
         GetArgRegname('reg1_name', 'reg1'),
         GetAccArgRegname,
         Equal('opcode_top', 0x90 >> 3),
         Apply('opcode', CatBits, ['opcode_top', 'reg1'], (5, 3)),
         Equal('not_byte_op', 1),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 0),
         Apply('args', Format, ['acc_regname', 'reg1_name'], '%s, %s')),

    Conj(Equal('opcode', 0x98),
         Switch('has_data16_prefix',
                # "Convert word to long".  'cwde' in Intel syntax.
                # Sign-extends %ax into %eax.
                (0, Equal('inst', 'cwtl')),
                # "Convert byte to word".  'cbw' in Intel syntax.
                # Sign-extends %al into %ax.
                (1, Equal('inst', 'cbtw'))),
         NoModRM,
         Equal('immediate_bytes', 0),
         Equal('has_inst_suffix', 0), # We add a suffix locally.
         Equal('args', '')),
    Conj(Equal('opcode', 0x99),
         Switch('has_data16_prefix',
                # "Convert long to double long".  'cdq' in Intel syntax.
                # Fills %edx with the top bit of %eax.
                (0, Equal('inst', 'cltd')),
                # "Convert word to double word".  'cwd' in Intel syntax.
                # Fills %dx with the top bit of %ax.
                (1, Equal('inst', 'cwtd'))),
         NoModRM,
         Equal('immediate_bytes', 0),
         Equal('has_inst_suffix', 0), # We add a suffix locally.
         Equal('args', '')),

    # objdump adds a suffix to make this 'calll' though arguably this
    # is superfluous.
    Conj(Equal('inst', 'calll'),
         Equal('opcode', 0xe8),
         NoDataOperation,
         Equal('has_data16_prefix', 0),
         Equal('immediate_bytes', 4),
         Equal('args', 'JUMP_DEST')),

    # String operations.
    Conj(Disj(Conj(Equal('inst', 'movs'),
                   OpcodePair(0xa4),
                   Equal('src_arg', '%ds:(%esi)'),
                   Equal('dest_arg', '%es:(%edi)')),
              Conj(Equal('inst', 'cmps'),
                   OpcodePair(0xa6),
                   Equal('src_arg', '%es:(%edi)'),
                   Equal('dest_arg', '%ds:(%esi)')),
              Conj(Equal('inst', 'stos'),
                   OpcodePair(0xaa),
                   GetAccArgRegname,
                   EqualVar('src_arg', 'acc_regname'),
                   Equal('dest_arg', '%es:(%edi)')),
              Conj(Equal('inst', 'lods'),
                   OpcodePair(0xac),
                   GetAccArgRegname,
                   Equal('src_arg', '%ds:(%esi)'),
                   EqualVar('dest_arg', 'acc_regname')),
              Conj(Equal('inst', 'scas'),
                   OpcodePair(0xae),
                   GetAccArgRegname,
                   Equal('src_arg', '%es:(%edi)'),
                   EqualVar('dest_arg', 'acc_regname'))),
         Apply('args', Format, ['src_arg', 'dest_arg'], '%s, %s'),
         DataOperationWithoutModRM,
         Equal('immediate_bytes', 0)),

    Conj(Equal('inst', 'test'), OpcodePair(0xa8), Format_imm_eax),
    )

TwoByteOpcodes = Disj(
    # 4-byte offset jumps.
    Conj(Equal('opcode', 0x0f),
         Equal('opcode2_top', 0x80 >> 4),
         Apply('opcode2', CatBits, ['opcode2_top', 'cond'], [4, 4]),
         ConditionCodes,
         NoDataOperation,
         Equal('has_data16_prefix', 0),
         Equal('immediate_bytes', 4),
         Equal('args', 'JUMP_DEST'),
         Apply('inst', Format, ['cond_name'], 'j%s')),
    )

def OptPrependByte(cond, byte_value, dest_var, src_var):
  return Switch(cond,
                (1, Apply(dest_var, PrependByte, [byte_value, src_var])),
                (0, EqualVar(dest_var, src_var)))

ConcatBytes = Conj(
    Equal('data16_byte', 0x66),
    OptPrependByte('has_data16_prefix', 'data16_byte', 'bytes', 'bytes0'),
    Apply('bytes0', PrependByte, ['opcode', 'bytes1']),
    OptPrependByte('has_opcode2', 'opcode2', 'bytes1', 'bytes2'),
    OptPrependByte('has_modrm_byte', 'modrm_byte', 'bytes2', 'bytes3'),
    OptPrependByte('has_sib_byte', 'sib_byte', 'bytes3', 'bytes4'),
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
    Switch('has_inst_suffix',
           (0, Equal('inst_suffix', '')),
           (1, Mapping3('has_data16_prefix', 'not_byte_op', 'inst_suffix',
                        [(0, 1, 'l'),
                         (1, 1, 'w'),
                         (0, 0, 'b')]))),
    Apply('desc', Format, ['inst', 'inst_suffix', 'args'], '%s%s %s'))


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

# These counts are multiplied by 2 for the movl/movw variants.
# Check all modrm/sib byte values.
movs = TestObjdump(Conj(Equal('opcode', 0x89), Equal('sib_byte', 0), Encode))
assert_eq(len(movs), 2 * 256)
movs = TestObjdump(Conj(Equal('opcode', 0x89), Equal('modrm_byte', 4), Encode))
assert_eq(len(movs), 2 * 256)
movs = TestObjdump(Conj(Equal('opcode', 0x89), Encode))
# There are 6376 combinations of modrm/sib bytes.
# There are 3*8 = 24 modrm bytes that indicate a sib byte follows.
# There are 256 - 24 = 232 modrm bytes without sib bytes.
# There are 256 * 24 = 6144 combinations of modrm bytes and sib bytes.
assert_eq(len(movs), 2 * (232 + 6144))

# 'lea' is special since it uses modrm but does not access memory.
# This means 'leal %eax, %eax' is not valid.  Check that we exclude it.
# We do not exclude redundant forms such as 'leal (%ebx), %eax'
# (which is equivalent to 'movl %ebx, %eax').
leas = TestObjdump(Conj(Equal('inst', 'lea'), Encode))
# Subtract the number of modrm byte values that are excluded.
assert_eq(len(leas), 2 * (6376 - 64))

# Test all instructions.  This is slower.
TestObjdump(Encode)
