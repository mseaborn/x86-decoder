
import subprocess

from memoize import Memoize


def Byte(x):
  return '%02x' % x


regs32 = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
regs16 = ('ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di')
regs8 = ('al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh')

regs_by_size = {
  32: regs32,
  16: regs16,
  8: regs8,
  }

mem_sizes = {
  32: 'DWORD PTR ',
  16: 'WORD PTR ',
  8: 'BYTE PTR ',
  'lea_mem': '',
  'mem32': 'DWORD PTR ',
  '8byte': 'QWORD PTR ',
  }

cond_codes = (
  'o', 'no', 'b', 'ae', 'e', 'ne', 'be', 'a',
  's', 'ns', 'p', 'np', 'l', 'ge', 'le', 'g',
  )


def AssertEq(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))


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
  AssertEq(value, 0)
  return tuple(parts)


@Memoize
def Sib(mod, rm_size, disp_size, disp_str, tail):
  nodes = []
  for index_reg, index_regname in enumerate(regs32):
    if index_reg == 4:
      # %esp is not accepted in the position '(reg, %esp)'.
      # In this context, register 4 is %eiz (an always-zero value).
      index_regname = 'eiz'
    for scale in (0, 1, 2, 3):
      # 5 is a special case and is not always %ebp.
      # %esi/%edi are missing from headings in table in doc.
      for base_reg, base_regname in enumerate(regs32):
        if index_regname == 'eiz' and base_regname == 'esp' and scale == 0:
          index_result = ''
        else:
          index_result = '%s*%s' % (index_regname, 1 << scale)
        if base_reg == 5 and mod == 0:
          base_regname = ''
          extra = 'VALUE32'
          extra2 = ['XX'] * 4
        else:
          extra = ''
          extra2 = []
        parts = [base_regname, index_result, extra, disp_str]
        bytes = ([Byte((scale << 6) | (index_reg << 3) | base_reg)]
                 + extra2
                 + ['XX'] * disp_size)
        nodes.append(TrieOfList(bytes,
                                DftLabel('rm_arg',
                                         FormatMemAccess(rm_size, parts),
                                         tail)))
  return MergeMany(nodes, NoMerge)


def FormatMemAccess(size, parts):
  parts = [part for part in parts if part != '']
  return '%s[%s]' % (mem_sizes[size], '+'.join(parts))


def ModRM1(rm_size, tail):
  yield (0, 5, TrieOfList(['XX'] * 4,
                          DftLabel('rm_arg',
                                   '%sds:VALUE32' % mem_sizes[rm_size],
                                   tail)))
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in enumerate(regs32):
      if reg2 == 4:
        # %esp is not accepted in this position.
        # 4 is a special value: adds SIB byte.
        continue
      if reg2 == 5 and mod == 0:
        continue
      yield (mod, reg2,
             TrieOfList(['XX'] * dispsize,
                        DftLabel('rm_arg', 
                                 FormatMemAccess(rm_size, [regname2, disp_str]),
                                 tail)))
    reg2 = 4
    yield (mod, reg2, Sib(mod, rm_size, dispsize, disp_str, tail))
  if rm_size not in ('lea_mem', 'mem32', '8byte'):
    mod = 3
    for reg2, regname2 in enumerate(regs_by_size[rm_size]):
      yield (mod, reg2, DftLabel('rm_arg', regname2, tail))


def ModRM(reg_size, rm_size, tail):
  for reg, regname in enumerate(regs_by_size[reg_size]):
    for mod, reg2, node in ModRM1(rm_size, tail):
      yield TrieOfList([Byte((mod << 6) | (reg << 3) | reg2)],
                       DftLabel('reg_arg', regname, node))


def ModRMSingleArg(arg_regs, opcode, tail):
  for mod, reg2, node in ModRM1(arg_regs, tail):
    yield TrieOfList([Byte((mod << 6) | (opcode << 3) | reg2)], node)


def TrieNode(children, accept=False):
  node = trie.Trie()
  node.children = children
  node.accept = accept
  return node


def TrieOfList(bytes, node):
  for byte in reversed(bytes):
    node = TrieNode({byte: node})
  return node


class DftLabel(object):

  def __init__(self, key, value, next):
    self.key = key
    self.value = value
    self.next = next

def DftLabels(pairs, node):
  for key, value in pairs:
    node = DftLabel(key, value, node)
  return node


# Assumes all the input nodes are immutable.
def MergeMany(nodes, merge_accept_types):
  if len(nodes) == 1:
    return list(nodes)[0]
  if len(nodes) == 0:
    return EmptyNode
  children = {}
  accept_types = set()

  if isinstance(nodes[0], DftLabel):
    for node in nodes:
      AssertEq(node.key, nodes[0].key)
      AssertEq(node.value, nodes[0].value)
    return DftLabel(nodes[0].key,
                    nodes[0].value,
                    MergeMany([node.next for node in nodes],
                              merge_accept_types))

  by_key = {}
  for node in nodes:
    accept_types.add(node.accept)
    for key, value in node.children.iteritems():
      by_key.setdefault(key, []).append(value)
  for key, subnodes in by_key.iteritems():
    children[key] = MergeMany(subnodes, merge_accept_types)

  if len(accept_types) == 1:
    accept = list(accept_types)[0]
  else:
    accept = merge_accept_types(accept_types)
  return trie.MakeInterned(children, accept)


def TrieSize(start_node, expand_wildcards):
  @Memoize
  def Rec(node):
    if isinstance(node, DftLabel):
      return Rec(node.next)
    x = 0
    if node.accept:
      x += 1
    if expand_wildcards and 'XX' in node.children:
      return x + 256 * Rec(node.children['XX'])
    else:
      for child in node.children.itervalues():
        x += Rec(child)
      return x

  return Rec(start_node)


import trie

def NoMerge(x):
  raise Exception('Cannot merge %r' % x)


@Memoize
def ImmediateNode(immediate_size):
  assert immediate_size in (0, 8, 16, 32), immediate_size
  return TrieOfList(['XX'] * (immediate_size / 8), trie.AcceptNode)


@Memoize
def ModRMNode(reg_size, rm_size, immediate_size):
  nodes = list(ModRM(reg_size, rm_size, ImmediateNode(immediate_size)))
  node = MergeMany(nodes, NoMerge)
  return TrieNode(dict((key, DftLabel('test_keep', key == '00' or key == 'ff',
                                      value))
                       for key, value in node.children.iteritems()))


def ModRMSingleArgNode(rm_size, opcode, labels, immediate_size):
  nodes = list(ModRMSingleArg(rm_size, opcode, ImmediateNode(immediate_size)))
  node = MergeMany(nodes, NoMerge)
  def Filter(byte):
    mod, reg1, reg2 = CatBitsRev(byte, [2, 3, 3])
    return (mod == 0 and reg2 == 0) or (mod == 3 and reg2 == 7)
  return TrieNode(dict((key, DftLabel('test_keep', Filter(int(key, 16)),
                                      DftLabels(labels, value)))
                       for key, value in node.children.iteritems()))


def FlattenTrie(node, bytes=[], labels=[]):
  if isinstance(node, DftLabel):
    for result in FlattenTrie(node.next, bytes, labels + [node]):
      yield result
  else:
    if node.accept:
      yield (bytes, labels)
    for byte, next in sorted(node.children.iteritems()):
      for result in FlattenTrie(next, bytes + [byte], labels):
        yield result


@Memoize
def FilterModRM(node):
  if isinstance(node, DftLabel):
    if node.key == 'test_keep' and not node.value:
      return trie.EmptyNode
    return DftLabel(node.key, node.value, FilterModRM(node.next))
  else:
    children = {}
    for key, value in node.children.iteritems():
      value = FilterModRM(value)
      if value != trie.EmptyNode:
        children[key] = value
    return TrieNode(children, node.accept)


def FilterPrefix(bytes, node):
  if len(bytes) == 0:
    return node
  else:
    return TrieNode({bytes[0]: FilterPrefix(bytes[1:],
                                            node.children[bytes[0]])},
                    node.accept)


def SubstSize(dec, size):
  def Subst(value):
    if value == 'imm8':
      return ('imm', 8)
    else:
      return (value, size)
  return map(Subst, dec)


def GetRoot():
  top_nodes = []

  def Add(bytes, instr_name, args, modrm_opcode=None):
    bytes = bytes.split()
    immediate_size = 0 # Size in bits
    rm_size = None
    reg_size = None
    out_args = []
    labels = []

    def SimpleArg(arg):
      out_args.append(arg)
      labels.append(('%s_arg' % arg, arg))

    for kind, size in args:
      if kind == 'imm':
        assert immediate_size == 0
        immediate_size = size
        SimpleArg('VALUE%i' % size)
      elif kind == 'rm':
        assert rm_size is None
        rm_size = size
        out_args.append(kind)
      elif kind == 'lea_mem':
        assert rm_size is None
        # For 'lea', the size is really irrelevant.
        rm_size = 'lea_mem'
        out_args.append('rm')
      elif kind == 'mem':
        assert rm_size is None
        rm_size = 'mem%i' % size
        out_args.append('rm')
      elif kind == 'reg':
        assert reg_size is None
        reg_size = size
        out_args.append(kind)
      elif kind == 'addr':
        assert immediate_size == 0
        immediate_size = 32
        SimpleArg('ds:VALUE32')
      elif kind == 'jump_dest':
        assert immediate_size == 0
        immediate_size = size
        SimpleArg('JUMP_DEST')
      elif kind == '*ax':
        SimpleArg(regs_by_size[size][0])
      elif kind in ('1', 'cl'):
        SimpleArg(kind)
      elif isinstance(kind, tuple) and len(kind) == 2 and kind[0] == 'fixreg':
        SimpleArg(regs_by_size[size][kind[1]])
      elif kind in ('es:[edi]', 'ds:[esi]'):
        SimpleArg(mem_sizes[size] + kind)
      else:
        raise AssertionError('Unknown arg type: %s' % repr(kind))

    labels.append(('args', out_args))
    labels.append(('instr_name', instr_name))

    if rm_size is not None and reg_size is not None:
      assert modrm_opcode is None
      node = ModRMNode(reg_size, rm_size, immediate_size)
    elif rm_size is not None and reg_size is None:
      assert modrm_opcode is not None
      node = ModRMSingleArgNode(rm_size, modrm_opcode, labels,
                                immediate_size)
      labels = []
    elif rm_size is None and reg_size is None:
      assert modrm_opcode is None
      node = ImmediateNode(immediate_size)
    else:
      raise AssertionError('Unknown type')
    node = DftLabels(labels, node)
    top_nodes.append(TrieOfList(bytes, node))

  def AddLW(opcode, instr, format, **kwargs):
    Add('66 ' + Byte(opcode), instr, SubstSize(format, 16), **kwargs)
    Add(Byte(opcode), instr, SubstSize(format, 32), **kwargs)

  # Like AddLW(), but takes a string rather than an int.
  # TODO: Unify these.
  def AddLW2(opcode, instr, format, **kwargs):
    Add('66 ' + opcode, instr, SubstSize(format, 16), **kwargs)
    Add(opcode, instr, SubstSize(format, 32), **kwargs)

  def AddPair(opcode, instr, format, **kwargs):
    Add(Byte(opcode), instr, SubstSize(format, 8), **kwargs)
    AddLW(opcode + 1, instr, format, **kwargs)

  # Like AddPair(), but also takes a prefix.
  def AddPair2(prefix, opcode, instr, format, **kwargs):
    Add(prefix + ' ' + Byte(opcode), instr, SubstSize(format, 8), **kwargs)
    AddLW2(prefix + ' ' + Byte(opcode + 1), instr, format, **kwargs)

  # Arithmetic instructions
  for arith_opcode, instr in enumerate(['add', 'or', 'adc', 'sbb',
                                        'and', 'sub', 'xor', 'cmp']):
    for format_num, format in enumerate([['rm', 'reg'],
                                         ['reg', 'rm'],
                                         ['*ax', 'imm']]):
      opcode = CatBits([arith_opcode, format_num, 0], [5, 2, 1])
      AddPair(opcode, instr, format)
    AddPair(0x80, instr, ['rm', 'imm'], modrm_opcode=arith_opcode)
    # 0x82 is a hole in the table.  We don't use AddPair(0x82) here
    # because 0x80 and 0x82 would be equivalent (both 8-bit ops with
    # imm8).
    AddLW(0x83, instr, ['rm', 'imm8'], modrm_opcode=arith_opcode)

  # Group 2: shift instructions
  for instr, modrm_opcode in [('rol', 0),
                              ('ror', 1),
                              ('rcl', 2),
                              ('rcr', 3),
                              ('shl', 4),
                              ('shr', 5),
                              # 6 is absent.
                              ('sar', 7),
                              ]:
    AddPair(0xc0, instr, ['rm', 'imm8'], modrm_opcode=modrm_opcode)
    AddPair(0xd0, instr, ['rm', '1'], modrm_opcode=modrm_opcode)
    AddPair(0xd2, instr, ['rm', 'cl'], modrm_opcode=modrm_opcode)

  for reg_num in range(8):
    Add(Byte(0x40 + reg_num), 'inc', [(('fixreg', reg_num), 32)])
    Add(Byte(0x48 + reg_num), 'dec', [(('fixreg', reg_num), 32)])
    Add(Byte(0x50 + reg_num), 'push', [(('fixreg', reg_num), 32)])
    Add(Byte(0x58 + reg_num), 'pop', [(('fixreg', reg_num), 32)])

  AddLW(0x68, 'push', ['imm'])
  Add('6a', 'push', [('imm', 8)])

  AddLW(0x69, 'imul', ['reg', 'rm', 'imm'])
  AddLW(0x6b, 'imul', ['reg', 'rm', 'imm8'])

  # Short (8-bit offset) conditional jumps
  for cond_num, cond_name in enumerate(cond_codes):
    Add(Byte(0x70 + cond_num), 'j' + cond_name, [('jump_dest', 8)])

  AddPair(0x84, 'test', ['rm', 'reg'])
  AddPair(0x86, 'xchg', ['rm', 'reg'])
  AddLW(0x8d, 'lea', ['reg', 'lea_mem'])
  AddLW(0x8f, 'pop', ['rm'], modrm_opcode=0)

  # 'nop' is really 'xchg %eax, %eax'.
  Add('90', 'nop', [])
  # 'pause' is really 'rep nop'.
  Add('f3 90', 'pause', [])
  for reg_num in range(8):
    if reg_num != 0:
      AddLW(0x90 + reg_num, 'xchg', [('fixreg', reg_num), '*ax'])

  # "Convert word to long".  Sign-extends %ax into %eax.
  Add('98', 'cwde', [])
  # "Convert byte to word".  Sign-extends %al into %ax.
  Add('66 98', 'cbw', [])
  # "Convert long to double long".  Fills %edx with the top bit of %eax.
  Add('99', 'cdq', [])
  # "Convert word to double word".  Fills %dx with the top bit of %ax.
  Add('66 99', 'cwd', [])
  # Note that assemblers and disassemblers treat 'fwait' as a prefix
  # such that 'fwait; fnXXX' is a shorthand for 'fXXX'.  (For example,
  # 'fwait; fnstenv ARG' can be written as 'fstenv ARG'.)  This might
  # cause cross-check tests to fail if these instructions are placed
  # together.  Really, though, fwait is an instruction in its own
  # right.
  Add('9b', 'fwait', [])
  Add('9e', 'sahf', [])
  Add('9f', 'lahf', [])
  Add('c9', 'leave', [])
  Add('f4', 'hlt', [])

  Add('e8', 'call', [('jump_dest', 32)])

  # String operations.
  for prefix_bytes, prefix in [('', ''),
                               ('f2', 'repnz '),
                               ('f3', 'rep ')]:
    AddPair2(prefix_bytes, 0xa4, prefix + 'movs', ['es:[edi]', 'ds:[esi]'])
    AddPair2(prefix_bytes, 0xaa, prefix + 'stos', ['es:[edi]', '*ax'])
    AddPair2(prefix_bytes, 0xac, prefix + 'lods', ['*ax', 'ds:[esi]'])
  for prefix_bytes, prefix in [('', ''),
                               ('f2', 'repnz '),
                               ('f3', 'repz ')]:
    AddPair2(prefix_bytes, 0xa6, prefix + 'cmps', ['ds:[esi]', 'es:[edi]'])
    AddPair2(prefix_bytes, 0xae, prefix + 'scas', ['*ax', 'es:[edi]'])

  AddPair(0xa8, 'test', ['*ax', 'imm'])

  Add('e3', 'jecxz', [('jump_dest', 8)])
  AddLW(0xe9, 'jmp', ['jump_dest'])
  Add('eb', 'jmp', [('jump_dest', 8)])

  Add('f5', 'cmc', []) # Complement carry flag
  Add('f8', 'clc', []) # Clear carry flag
  Add('f9', 'stc', []) # Set carry flag
  Add('fc', 'cld', []) # Clear direction flag
  Add('fd', 'std', []) # Set direction flag

  # Group 3
  AddPair(0xf6, 'test', ['rm', 'imm'], modrm_opcode=0)
  for instr, modrm_opcode in [('not', 2),
                              ('neg', 3),
                              ('mul', 4),
                              ('imul', 5),
                              ('div', 6),
                              ('idiv', 7)]:
    AddPair(0xf6, instr, ['rm'], modrm_opcode=modrm_opcode)

  # Group 4/5
  AddPair(0xfe, 'inc', ['rm'], modrm_opcode=0)
  AddPair(0xfe, 'dec', ['rm'], modrm_opcode=1)
  # Group 5
  AddLW(0xff, 'push', ['rm'], modrm_opcode=6)
  # TODO: We don't want to allow the data16 prefix on jmp/call.
  AddLW(0xff, 'call', ['rm'], modrm_opcode=2)
  AddLW(0xff, 'jmp', ['rm'], modrm_opcode=4)

  AddPair(0x88, 'mov', ['rm', 'reg'])
  AddPair(0x8a, 'mov', ['reg', 'rm'])
  AddPair(0xc6, 'mov', ['rm', 'imm'], modrm_opcode=0)
  AddPair(0xa0, 'mov', ['*ax', 'addr'])
  AddPair(0xa2, 'mov', ['addr', '*ax'])
  for reg_num in range(8):
    Add(Byte(0xb0 + reg_num), 'mov', [(('fixreg', reg_num), 8), ('imm', 8)])
    AddLW(0xb8 + reg_num, 'mov', [('fixreg', reg_num), 'imm'])

  # Two-byte opcodes.

  for cond_num, cond_name in enumerate(cond_codes):
    # Conditional move.  Added in P6.
    AddLW2('0f ' + Byte(0x40 + cond_num), 'cmov' + cond_name, ['reg', 'rm'])
    # 4-byte offset jumps.
    Add('0f ' + Byte(0x80 + cond_num), 'j' + cond_name, [('jump_dest', 32)])
    # Byte set on condition
    Add('0f ' + Byte(0x90 + cond_num), 'set' + cond_name, [('rm', 8)],
        modrm_opcode=0)

  # Bit test/set/clear operations
  AddLW2('0f a3', 'bt', ['rm', 'reg'])
  AddLW2('0f ab', 'bts', ['rm', 'reg'])
  AddLW2('0f b3', 'btr', ['rm', 'reg'])
  AddLW2('0f bb', 'btc', ['rm', 'reg'])
  # Group 8
  AddLW2('0f ba', 'bt', ['rm', 'imm8'], modrm_opcode=4)
  AddLW2('0f ba', 'bts', ['rm', 'imm8'], modrm_opcode=5)
  AddLW2('0f ba', 'btr', ['rm', 'imm8'], modrm_opcode=6)
  AddLW2('0f ba', 'btc', ['rm', 'imm8'], modrm_opcode=7)

  # Bit shift left/right
  AddLW2('0f a4', 'shld', ['rm', 'reg', 'imm8'])
  AddLW2('0f a5', 'shld', ['rm', 'reg', 'cl'])
  AddLW2('0f ac', 'shrd', ['rm', 'reg', 'imm8'])
  AddLW2('0f ad', 'shrd', ['rm', 'reg', 'cl'])

  AddLW2('0f af', 'imul', ['reg', 'rm'])

  # Bit scan forwards/reverse
  AddLW2('0f bc', 'bsf', ['reg', 'rm'])
  AddLW2('0f bd', 'bsr', ['reg', 'rm'])

  # Move with zero/sign extend.
  Add('0f b6', 'movzx', [('reg', 32), ('rm', 8)])
  Add('0f b7', 'movzx', [('reg', 32), ('rm', 16)])
  Add('0f be', 'movsx', [('reg', 32), ('rm', 8)])
  Add('0f bf', 'movsx', [('reg', 32), ('rm', 16)])

  # Added in the 486.
  AddPair2('0f', 0xb0, 'cmpxchg', ['rm', 'reg'])
  AddPair2('0f', 0xc0, 'xadd', ['rm', 'reg'])
  Add('0f c7', 'cmpxchg8b', [('rm', '8byte')], modrm_opcode=1)
  for reg_num in range(8):
    # bswap is undefined when used with the data16 prefix (because
    # xchgw could be used for swapping bytes in a word instead),
    # although objdump decodes such instructions.
    Add('0f ' + Byte(0xc8 + reg_num), 'bswap', [(('fixreg', reg_num), 32)])

  # SSE
  Add('0f ae', 'ldmxcsr', [('mem', 32)], modrm_opcode=2)
  Add('0f ae', 'stmxcsr', [('mem', 32)], modrm_opcode=3)

  return MergeMany(top_nodes, NoMerge)


def InstrFromLabels(args):
  instr_args = ', '.join([args['%s_arg' % arg] for arg in args['args']])
  return '%s %s' % (args['instr_name'], instr_args)

def GetAll(node):
  for bytes, labels in FlattenTrie(node):
    args = dict((label.key, label.value) for label in labels)
    yield (bytes, InstrFromLabels(args))

import objdump_check

print 'Building trie...'
trie_root = GetRoot()
print 'Size:'
print TrieSize(trie_root, False)
print 'Testing...'
filtered_trie = FilterModRM(trie_root)
for bytes, labels in GetAll(filtered_trie):
  print '%s:%s' % (' '.join(bytes), labels)
objdump_check.DisassembleTest(lambda: GetAll(filtered_trie), bits=32)

print 'Testing all ModRM bytes...'
objdump_check.DisassembleTest(lambda: GetAll(FilterPrefix(['01'], trie_root)),
                              bits=32)
