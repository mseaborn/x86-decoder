
import objdump_check


def Set(ctx, var, i):
  if var in ctx:
    if ctx[var] == i:
      yield ctx
  else:
    copy = ctx.copy()
    copy[var] = i
    yield copy

def ForRange(var, upto):
  def Func(ctx):
    for i in xrange(upto):
      for x in Set(ctx, var, i):
        yield x
  return Func

def Equal(var, i):
  def Func(ctx):
    for x in Set(ctx, var, i):
      yield x
  return Func

def EqualVar(var1, var2):
  def Func(ctx):
    for x in Set(ctx, var1, ctx[var2]):
      yield x
  return Func

def NotEqual(var, i):
  def Func(ctx):
    if ctx[var] != i:
      yield ctx
  return Func

def Apply(dest_var, func, arg_vars, *args):
  def Func(ctx):
    result = func([ctx[var] for var in arg_vars], *args)
    for x in Set(ctx, dest_var, result):
      yield x
  return Func

def Conj2(term1, term2):
  def Func(ctx):
    for x in term1(ctx):
      for y in term2(x):
        yield y
  return Func

def Conj(*terms):
  return reduce(Conj2, terms)

def Disj(*terms):
  def Func(ctx):
    for term in terms:
      for x in term(ctx):
        yield x
  return Func


# Syntactic sugar.
def Switch(var, *branches):
  return Disj(*[Conj(Equal(var, x), code)
                for x, code in branches])


def CatBits(values, sizes_in_bits):
  result = 0
  for value, size_in_bits in zip(values, sizes_in_bits):
    assert isinstance(value, int)
    assert 0 <= value
    assert value < (1 << size_in_bits)
    result = (result << size_in_bits) | value
  return result

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

def Bytes(args):
  return ['%02x' % byte for byte in args]

def AppendWildcard(args):
  bytes, size = args
  return bytes + ['XX'] * size

def AppendByte(args):
  bytes, byte = args
  return bytes + Bytes([byte])

def Format(args, format):
  return format % tuple(args)


SibEncoding = Conj(
    ForRange('scale', 4),
    ForRange('indexreg', 8),
    ForRange('basereg', 8),
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
    ForRange('reg2', 8),
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
    ForRange('reg2', 8),
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
ModRM = Conj(ForRange('reg1', 8),
             Apply('reg1_name', RegName, ['reg1']),
             Disj(ModRMRegister,
                  ModRMAbsoluteAddr,
                  ModRMDisp,
                  ModRMSib,
                  ),
             Apply('modrm_byte', CatBits, ['mod', 'reg1', 'reg2'], [2,3,3]))

Mov = Disj(Conj(Equal('inst', 'movl'), Equal('opcode', 0x89), ModRM,
                Equal('args_format', 'reg rm')),
           Conj(Equal('inst', 'movl'), Equal('opcode', 0x8b), ModRM,
                Equal('args_format', 'rm reg')))

Encode = Conj(Mov,
              Apply('bytes1', Bytes, ['opcode', 'modrm_byte']),
              Switch('has_sib_byte',
                     (0, EqualVar('bytes2', 'bytes1')),
                     (1, Apply('bytes2', AppendByte, ['bytes1', 'sib_byte']))),
              Apply('bytes', AppendWildcard, ['bytes2', 'displacement_bytes']),
              Switch('args_format',
                     ('reg rm', Apply('args', Format, ['reg1_name', 'rm_arg'],
                                      '%s, %s')),
                     ('rm reg', Apply('args', Format, ['rm_arg', 'reg1_name'],
                                      '%s, %s')),
                     ),
              Apply('desc', Format, ['inst', 'args'], '%s %s'))


if False:
  import pprint
  init = {}
  for x in Encode(init):
    pprint.pprint(x)

def GetAll():
  return ((info['bytes'], info['desc']) for info in Encode({}))

bits = 32
objdump_check.DisassembleTest(GetAll, bits)
