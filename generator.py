
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


def TrieNode(children):
  node = trie.Trie()
  node.children = children
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
  return trie.MergeMany(nodes, NoMerge)


@Memoize
def ModRMSingleArgNode(rm_size, opcode, immediate_size):
  nodes = []
  tail = TrieOfList(['XX'] * immediate_size, trie.AcceptNode)
  for bytes, rm_arg in ModRMSingleArg(rm_size, opcode):
    nodes.append(TrieOfList(bytes,
                            DftLabels([('rm_arg', rm_arg)], tail)))
  return trie.MergeMany(nodes, NoMerge)


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
      node = DftLabel('imm_arg', 'VALUE%i' % size,
                      ModRMSingleArgNode(sizes[0], modrm_opcode, sizes[1] / 8))
    else:
      xxxx
    top_nodes.append(TrieOfList(bytes, DftLabels([('instr_name', instr_name),
                                                  ('args', parts)],
                                                 node)))

  Add('01', 'add', [('rm', 32), ('reg', 32)])
  Add('03', 'add', [('reg', 32), ('rm', 32)])
  Add('80', 'add', [('rm', 8), ('imm', 8)], modrm_opcode=0)
  Add('0f b6', 'movzx', [('reg', 32), ('rm', 8)])
  Add('0f b7', 'movzx', [('reg', 32), ('rm', 16)])
  Add('0f be', 'movsx', [('reg', 32), ('rm', 8)])
  Add('0f bf', 'movsx', [('reg', 32), ('rm', 16)])
  return trie.MergeMany(top_nodes, NoMerge)

def GetAll():
  for bytes, labels in FlattenTrie(GetRoot()):
    args = dict((label.key, label.value) for label in labels)
    i_args = ', '.join([args['%s_arg' % arg] for arg in args['args']])
    instr = '%s %s' % (args['instr_name'], i_args)
    yield (bytes, instr)

import objdump_check

print TrieSize(GetRoot(), False)

objdump_check.DisassembleTest(GetAll, bits=32)
