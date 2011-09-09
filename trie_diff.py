
import sys

from memoize import Memoize
import trie


def Diff(node1, node2, context=[]):
  if node1 == node2:
    return
  if node1.accept != node2.accept:
    print '%r -> %r: %s' % (node1.accept, node2.accept, ' '.join(context))
  keys = set()
  keys.update(node1.children.iterkeys())
  keys.update(node2.children.iterkeys())
  for key in sorted(keys):
    Diff(node1.children.get(key, trie.EmptyNode),
         node2.children.get(key, trie.EmptyNode),
         context + [key])


# Identify wildcard edges, turning implicit (expanded-out) wildcards
# into explicit 'XX' wildcards.  This is useful when one or both of
# the diff inputs has had wildcards expanded out.  Explicit wildcards
# are better when enumerating instructions.
def SimplifyWildcards(root):
  @Memoize
  def Rec(node):
    dests = set(node.children.itervalues())
    if len(dests) == 1 and len(set(node.children.iterkeys())) == 256:
      keys = sorted(node.children.iterkeys())
      assert keys == ['%02x' % c for c in range(256)], keys
      children = {'XX': Rec(list(dests)[0])}
    else:
      children = node.children
    return trie.MakeInterned(dict((key, Rec(value))
                                  for key, value in children.iteritems()),
                             node.accept)

  return Rec(root)


def Main(args):
  assert len(args) == 2
  roots = [SimplifyWildcards(trie.TrieFromFile(filename))
           for filename in args]
  Diff(roots[0], roots[1])


if __name__ == '__main__':
  Main(sys.argv[1:])
