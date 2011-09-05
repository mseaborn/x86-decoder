
import subprocess
import objdump


def Byte(x):
  return '%02x' % x


regs32 = (
  (0, 'eax'),
  (1, 'ecx'),
  (2, 'edx'),
  (3, 'ebx'),
  (4, 'esp'),
  (5, 'ebp'),
  (6, 'esi'),
  (7, 'edi'))

regs16 = (
  (0, 'ax'),
  (1, 'cx'),
  (2, 'dx'),
  (3, 'bx'),
  (4, 'sp'),
  (5, 'bp'),
  (6, 'si'),
  (7, 'di'))

regs8 = (
  (0, 'al'),
  (1, 'cl'),
  (2, 'dl'),
  (3, 'bl'),
  (4, 'ah'),
  (5, 'ch'),
  (6, 'dh'),
  (7, 'bh'))

regs_by_size = {
  32: regs32,
  16: regs16,
  8: regs8,
  }

mem_sizes = {
  32: 'DWORD',
  16: 'WORD',
  8: 'BYTE',
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


def Sib(mod):
  for index_reg, index_regname in regs32:
    if index_reg == 4:
      # %esp is not accepted in the position '(reg, %esp)'.
      # In this context, register 4 is %eiz (an always-zero value).
      index_regname = 'eiz'
    for scale in (0, 1, 2, 3):
      # 5 is a special case and is not always %ebp.
      # %esi/%edi are missing from headings in table in doc.
      for base_reg, base_regname in regs32:
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
        parts = [base_regname, index_result, extra]
        yield [Byte((scale << 6) | (index_reg << 3) | base_reg)] + extra2, parts


def FormatMemAccess(size, parts):
  parts = [part for part in parts if part != '']
  return '%s PTR [%s]' % (mem_sizes[size], '+'.join(parts))


def ModRM1(rm_size):
  yield (0, 5, ['XX'] * 4, '%s PTR ds:VALUE32' % mem_sizes[rm_size])
  for mod, dispsize, disp_str in ((0, 0, ''),
                                  (1, 1, 'VALUE8'),
                                  (2, 4, 'VALUE32')):
    for reg2, regname2 in regs32:
      if reg2 == 4:
        # %esp is not accepted in this position.
        # 4 is a special value: adds SIB byte.
        continue
      if reg2 == 5 and mod == 0:
        continue
      yield (mod, reg2, ['XX'] * dispsize,
             FormatMemAccess(rm_size, [regname2, disp_str]))
    reg2 = 4
    for sib_bytes, desc in Sib(mod):
      yield (mod, reg2, sib_bytes + ['XX'] * dispsize,
             FormatMemAccess(rm_size, desc + [disp_str]))
  mod = 3
  for reg2, regname2 in regs_by_size[rm_size]:
    yield (mod, reg2, [], regname2)


def ModRM(reg_size, rm_size):
  for reg, regname in regs_by_size[reg_size]:
    for mod, reg2, rest, desc in ModRM1(rm_size):
      yield ([Byte((mod << 6) | (reg << 3) | reg2)] + rest, regname, desc)


def ModRMSingleArg(arg_regs, opcode):
  for mod, reg2, rest, desc in ModRM1(arg_regs):
    yield ([Byte((mod << 6) | (opcode << 3) | reg2)] + rest, desc)


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


from memoize import Memoize

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
def ModRMNode(reg_size, rm_size, immediate_size):
  nodes = []
  tail = TrieOfList(['XX'] * immediate_size, trie.AcceptNode)
  for bytes, reg_arg, rm_arg in ModRM(reg_size, rm_size):
    nodes.append(TrieOfList(bytes,
                            DftLabels([('reg_arg', reg_arg),
                                       ('rm_arg', rm_arg)], tail)))
  node = MergeMany(nodes, NoMerge)
  return TrieNode(dict((key, DftLabel('test_keep', key == '00', value))
                       for key, value in node.children.iteritems()))


@Memoize
def ModRMSingleArgNode(rm_size, opcode, instr_name, immediate_size):
  nodes = []
  tail = TrieOfList(['XX'] * immediate_size, trie.AcceptNode)
  for bytes, rm_arg in ModRMSingleArg(rm_size, opcode):
    nodes.append(TrieOfList(bytes,
                            DftLabels([('rm_arg', rm_arg)], tail)))
  node = MergeMany(nodes, NoMerge)
  def Filter(byte):
    mod, reg1, reg2 = CatBitsRev(byte, [2, 3, 3])
    return mod == 0 and reg2 == 0
  return TrieNode(dict((key, DftLabel('test_keep', Filter(int(key, 16)),
                                      DftLabel('instr_name', instr_name,
                                               value)))
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
    immediate_size = 0 # Size in bytes
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
        immediate_size = size / 8
        SimpleArg('VALUE%i' % size)
      elif kind == 'rm':
        assert rm_size is None
        rm_size = size
        out_args.append(kind)
      elif kind == 'reg':
        assert reg_size is None
        reg_size = size
        out_args.append(kind)
      elif kind == 'addr':
        assert immediate_size == 0
        immediate_size = 4
        SimpleArg('ds:VALUE32')
      elif kind == 'jump_dest':
        assert immediate_size == 0
        immediate_size = size / 8
        SimpleArg('JUMP_DEST')
      elif kind == '*ax':
        SimpleArg(regs_by_size[size][0][1])
      elif kind in ('1', 'cl'):
        SimpleArg(kind)
      elif isinstance(kind, tuple) and len(kind) == 2 and kind[0] == 'fixreg':
        SimpleArg(regs_by_size[size][kind[1]][1])
      else:
        raise AssertionError('Unknown arg type: %s' % repr(kind))

    if rm_size is not None and reg_size is not None:
      assert modrm_opcode is None
      node = ModRMNode(reg_size, rm_size, immediate_size)
    elif rm_size is not None and reg_size is None:
      assert modrm_opcode is not None
      node = ModRMSingleArgNode(rm_size, modrm_opcode, instr_name,
                                immediate_size)
    elif rm_size is None and reg_size is None:
      assert modrm_opcode is None
      node = TrieOfList(['XX'] * immediate_size, trie.AcceptNode)
    else:
      raise AssertionError('Unknown type')
    node = DftLabels(labels, node)
    node = DftLabel('args', out_args, node)
    if modrm_opcode is None:
      node = DftLabel('instr_name', instr_name, node)
    top_nodes.append(TrieOfList(bytes, node))

  def AddLW(opcode, instr, format, **kwargs):
    Add('66 ' + Byte(opcode), instr, SubstSize(format, 16), **kwargs)
    Add(Byte(opcode), instr, SubstSize(format, 32), **kwargs)

  def AddPair(opcode, instr, format, **kwargs):
    Add(Byte(opcode), instr, SubstSize(format, 8), **kwargs)
    AddLW(opcode + 1, instr, format, **kwargs)

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

  Add('f4', 'hlt', [])
  Add('90', 'nop', [])
  AddPair(0x88, 'mov', ['rm', 'reg'])
  AddPair(0x8a, 'mov', ['reg', 'rm'])
  AddPair(0xc6, 'mov', ['rm', 'imm'], modrm_opcode=0)
  AddPair(0xa0, 'mov', ['*ax', 'addr'])
  AddPair(0xa2, 'mov', ['addr', '*ax'])
  for reg_num in range(8):
    Add(Byte(0xb0 + reg_num), 'mov', [(('fixreg', reg_num), 8), ('imm', 8)])
    AddLW(0xb8 + reg_num, 'mov', [('fixreg', reg_num), 'imm'])
  Add('0f b6', 'movzx', [('reg', 32), ('rm', 8)])
  Add('0f b7', 'movzx', [('reg', 32), ('rm', 16)])
  Add('0f be', 'movsx', [('reg', 32), ('rm', 8)])
  Add('0f bf', 'movsx', [('reg', 32), ('rm', 16)])
  return MergeMany(top_nodes, NoMerge)

def InstrFromLabels(args):
  instr_args = ', '.join([args['%s_arg' % arg] for arg in args['args']])
  return '%s %s' % (args['instr_name'], instr_args)

def GetAll(node):
  for bytes, labels in FlattenTrie(node):
    args = dict((label.key, label.value) for label in labels)
    yield (bytes, InstrFromLabels(args))

import objdump_check

trie_root = GetRoot()
print TrieSize(trie_root, False)
print 'testing...'
filtered_trie = FilterModRM(trie_root)
for bytes, labels in GetAll(filtered_trie):
  print '%s:%s' % (' '.join(bytes), labels)
objdump_check.DisassembleTest(lambda: GetAll(filtered_trie), bits=32)
