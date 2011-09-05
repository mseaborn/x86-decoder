
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


def GetRoot():
  top_nodes = []

  def Add(bytes, instr_name, args, modrm_opcode=None):
    bytes = bytes.split()
    parts = [kind for kind, size in args]
    sizes = [size for kind, size in args]
    if parts == ['rm', 'reg']:
      assert modrm_opcode is None
      node = ModRMNode(sizes[1], sizes[0], 0)
    elif parts == ['reg', 'rm']:
      assert modrm_opcode is None
      node = ModRMNode(sizes[0], sizes[1], 0)
    elif parts == ['rm', 'imm']:
      assert modrm_opcode is not None
      node = DftLabel('imm_arg', 'VALUE%i' % size,
                      ModRMSingleArgNode(sizes[0], modrm_opcode, instr_name,
                                         sizes[1] / 8))
    elif parts == ['*ax', 'imm']:
      assert modrm_opcode is None
      node = DftLabels([('imm_arg', 'VALUE%i' % size),
                        ('*ax_arg', regs_by_size[size][0][1])],
                       TrieOfList(['XX'] * (sizes[1] / 8), trie.AcceptNode))
    else:
      raise AssertionError('Unknown pattern: %r' % args)
    node = DftLabel('args', parts, node)
    if modrm_opcode is None:
      node = DftLabel('instr_name', instr_name, node)
    top_nodes.append(TrieOfList(bytes, node))

  def AddPair(opcode, instr, format, **kwargs):
    Add(Byte(opcode), instr, [(arg, 8) for arg in format], **kwargs)
    Add('66 ' + Byte(opcode + 1), instr, [(arg, 16) for arg in format], **kwargs)
    Add(Byte(opcode + 1), instr, [(arg, 32) for arg in format], **kwargs)

  for arith_opcode, instr in enumerate(['add', 'or', 'adc', 'sbb',
                                        'and', 'sub', 'xor', 'cmp']):
    for format_num, format in enumerate([['rm', 'reg'],
                                         ['reg', 'rm'],
                                         ['*ax', 'imm']]):
      opcode = CatBits([arith_opcode, format_num, 0], [5, 2, 1])
      AddPair(opcode, instr, format)
    AddPair(0x80, instr, ['rm', 'imm'], modrm_opcode=arith_opcode)
    # 0x82 is a hole in the table...
    Add('66 83', instr, [('rm', 16), ('imm', 8)], modrm_opcode=arith_opcode)
    Add('83', instr, [('rm', 32), ('imm', 8)], modrm_opcode=arith_opcode)

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
