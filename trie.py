
class Trie(object):

  def __init__(self):
    self.accept = False
    self.children = {}

  def Intern(self, node_hash, node_list):
    children = dict((key, val.Intern(node_hash, node_list))
                    for key, val in sorted(self.children.iteritems()))
    # Optimise.  It is always safe to remove edges when the trie
    # describes a whitelist: it would just remove instructions that
    # are accepted.
    if 'XX' in children:
      for key in list(children.iterkeys()): # Must copy here
        if key != 'XX':
          del children[key]
    key = (self.accept, tuple(sorted(children.iteritems())))
    copy = node_hash.get(key)
    if copy is None:
      copy = Trie()
      copy.accept = self.accept
      copy.children = dict(children)
      node_hash[key] = copy
      node_list.append(copy)
    return copy


def Add(root, bytes, instr):
  node = root
  for byte in bytes:
    if byte not in node.children:
      new = Trie()
      node.children[byte] = new
    node = node.children[byte]
  node.accept = True


def Pr(node, stream, indent=0):
  ind = '  ' * indent
  if node.accept:
    stream.write(ind + 'accept\n')
  if 'XX' in node.children and len(node.children) > 1:
    stream.write(ind + 'both\n')
  for key, val in sorted(node.children.iteritems()):
    stream.write(ind + key + '\n')
    Pr(val, stream, indent + 1)

def Pr(node, stream, prev=''):
  if node.accept:
    stream.write(prev + ' accept\n')
  if 'XX' in node.children and len(node.children) > 1:
    stream.write(prev + ' both\n')
  for key, val in sorted(node.children.iteritems()):
    stream.write(prev + ' ' + key + '\n')
    Pr(val, stream, prev + ' ' + key)


def Main():
  print 'populating trie...'
  root = Trie()
  for line in open('patterns'):
    bytes, instr = line.strip().split(':', 1)
    bytes = bytes.split(' ')
    Add(root, bytes, instr)

  print 'minimising trie...'
  node_dict = {}
  node_list = []
  new_root = root.Intern(node_dict, node_list)
  print len(node_dict)

  if False:
    fh = open('trie1', 'w')
    Pr(root, fh)
    fh.close()

    fh = open('trie2', 'w')
    Pr(new_root, fh)
    fh.close()

  for i, node in enumerate(node_list):
    node.id = i
  info = {"start": new_root.id,
          "map": dict((node.id, dict((key, dest.id)
                                     for key, dest in node.children.iteritems()))
                      for node in node_list),
          "accepts": dict((node.id, node.accept)
                          for node in node_list)}
  fh = open('trie_data', 'w')
  fh.write(repr(info))
  fh.close()


def Dump():
  for i, node in enumerate(node_list):
    node.id = i
  for i, node in enumerate(node_list):
    print 'node %i:' % i
    if node.accept:
      print 'ACCEPT'
    for key, val in sorted(node.children.iteritems()):
      print '%s -> %s' % (key, val.id)


if __name__ == '__main__':
  Main()
