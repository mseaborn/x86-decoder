# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import trie

# Converts the trie/DFA to a C file.


# As an optimisation, group together accepting states of the same
# type.  This makes it possible to check for an accepting type with a
# range check.
def SortKey(node):
  if node.accept != False:
    return [0, node.accept]
  else:
    return [1]


def WriteTransitionTable(out, nodes, node_to_id):
  out.write('static const uint8_t trie_table[][256] = {\n')
  for node in nodes:
    out.write('  /* state %i: accept=%s */ {\n' %
              (node_to_id[node], node.accept))
    if 'XX' in node.children:
      assert len(node.children) == 1, node.children
      bytes = [node_to_id[node.children['XX']]] * 256
    else:
      bytes = [0] * 256
      for byte, dest_node in node.children.iteritems():
        bytes[int(byte, 16)] = node_to_id[dest_node]
    out.write(' ' * 11 + '/* ')
    out.write('  '.join('X%x' % lower for lower in xrange(16)))
    out.write(' */\n')
    for upper in xrange(16):
      out.write('    /* %xX */  ' % upper)
      out.write(', '.join('%2i' % bytes[upper*16 + lower]
                          for lower in xrange(16)))
      out.write(',\n')
    out.write('  },\n')
  out.write('};\n')
  out.write("""
static inline uint8_t trie_lookup(uint8_t state, uint8_t byte) {
  return trie_table[state][byte];
}
""")


def Main():
  trie_file = 'x86_32.trie'

  root_node = trie.TrieFromFile(trie_file)
  nodes = sorted(trie.GetAllNodes(root_node), key=SortKey)
  # Node ID 0 is reserved as the rejecting state.  For a little extra
  # safety, all transitions from node 0 lead to node 0.
  nodes = [trie.EmptyNode] + nodes
  node_to_id = dict((node, index) for index, node in enumerate(nodes))

  out = open('trie_table.h', 'w')
  out.write('\n#include <stdint.h>\n\n')

  out.write('static const int trie_start = %i;\n\n' % node_to_id[root_node])

  accept_types = set(node.accept for node in nodes
                     if node.accept != False)
  # This accept type disappears when relative jumps with 16-bit
  # offsets are disallowed, but it is nice to keep the C handler code
  # around.  Such jumps are not unsafe and could be allowed.
  accept_types.add('jump_rel2')
  assert 'jump_rel1' in accept_types
  assert 'jump_rel4' in accept_types

  for accept_type in sorted(accept_types):
    acceptors = [node_to_id[node] for node in nodes
                 if node.accept == accept_type]
    print 'Type %r has %i acceptors' % (accept_type, len(acceptors))
    if len(acceptors) > 0:
      expr = ' || '.join('node_id == %i' % node_id for node_id in acceptors)
    else:
      expr = '0 /* These instructions are currently disallowed */'
    out.write('static inline int trie_accepts_%s(int node_id) '
              '{\n  return %s;\n}\n\n'
              % (accept_type, expr))

  WriteTransitionTable(out, nodes, node_to_id)
  out.close()


if __name__ == '__main__':
  Main()
