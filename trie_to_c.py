
import trie

# Converts the trie/DFA to a C file.


def Main():
  trie_file = 'new.trie'

  root_node = trie.TrieFromFile(trie_file)
  # Node ID 0 is reserved as the rejecting state.  For a little extra
  # safety, all transitions from node 0 lead to node 0.
  nodes = [trie.EmptyNode] + trie.GetAllNodes(root_node)
  node_to_id = dict((node, index) for index, node in enumerate(nodes))

  out = open('trie_table.h', 'w')
  out.write('#include <stdint.h>\n')
  out.write('static const uint8_t trie_table[][256] = {\n')
  for node in nodes:
    out.write('  /* 0x%02x */ { ' % node_to_id[node])
    if 'XX' in node.children:
      assert len(node.children) == 1, node.children
      bytes = [node_to_id[node.children['XX']]] * 256
    else:
      bytes = [0] * 256
      for byte, dest_node in node.children.iteritems():
        bytes[int(byte, 16)] = node_to_id[dest_node]
    out.write(', '.join('0x%02x' % dest_id for dest_id in bytes))
    out.write(' },\n')
  out.write('};\n')

  out.write('static const int trie_start = %i;\n' % node_to_id[root_node])

  accepters = [node_to_id[node] for node in nodes if node.accept]
  assert len(accepters) == 1
  out.write('static inline int trie_accepts(int node_id) '
            '{ return node_id == %i; }\n'
            % accepters[0])
  out.close()


if __name__ == '__main__':
  Main()
