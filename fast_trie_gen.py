
import time

from memoize import Memoize
import constraint_gen
import logic
import trie


def GetApplyConstraint(ctx, var, func):
  for con in ctx.waiting.get(var, []):
    if (isinstance(con, logic.ApplyConstraint) and
        con.func == func and
        con.dest_var == var):
      yield con


def GetVarValues(ctx, var):
  if var in ctx.vars:
    return [ctx.vars[var]]
  else:
    return sorted(ctx.varrs[var])


def Permutations(items):
  if len(items) == 0:
    yield []
  else:
    for x in items[0]:
      for xs in Permutations(items[1:]):
        yield [x] + xs


# TODO: Don't convert ints to strings, because this slows things down.
def FormatByte(byte):
  return '%02x' % byte


def TriePrepend(bytes, tail_trie):
  children = {}
  for byte in bytes:
    children[FormatByte(byte)] = tail_trie
  return trie.MakeInterned(children, False)


@Memoize
def TrieCatPrepend(vals, sizes, tail_trie):
  bytes = [constraint_gen.CatBits(perm, sizes)
           for perm in Permutations(vals)]
  return TriePrepend(bytes, tail_trie)


def FollowByte(ctx, var, tail_trie):
  if var in ctx.vars:
    return TriePrepend([ctx.vars[var]], tail_trie)
  for con in GetApplyConstraint(ctx, var, constraint_gen.CatBits):
    vals = tuple(tuple(sorted(GetVarValues(ctx, arg))) for arg in con.arg_vars)
    sizes = tuple(con.args[0])
    return TrieCatPrepend(vals, sizes, tail_trie)
  raise AssertionError('FollowByte failed')


def FollowBytes(ctx, var):
  if var in ctx.vars:
    tail = trie.MakeInterned({}, ctx.vars['accept_type'])
    return TrieOfList(tuple(ctx.vars[var]), tail)
  for con in ctx.waiting.get(var, []):
    if isinstance(con, logic.EqualVarConstraint) and con.var1 == var:
      return FollowBytes(ctx, con.var2)
  for con in GetApplyConstraint(ctx, var, constraint_gen.PrependByte):
    return FollowByte(ctx, con.arg_vars[0],
                      FollowBytes(ctx, con.arg_vars[1]))
  raise AssertionError('FollowBytes failed')


@Memoize
def TrieOfList(bytes, node):
  for byte in reversed(bytes):
    if byte == 'XX':
      children = dict((FormatByte(x), node) for x in xrange(256))
    else:
      children = {byte: node}
    node = trie.MakeInterned(children, False)
  return node


def Time(func):
  t0 = time.time()
  r = func()
  t1 = time.time()
  print '%s took %fs' % (func, t1 - t0)
  return r


def MergeAcceptTypes(accept_types):
  if accept_types == set(['normal_inst', False]):
    return 'superinst_start'
  else:
    raise AssertionError('Cannot merge %r' % accept_types)


class Generator(object):

  def __init__(self):
    self.ctx = logic.Context()
    self.got_nodes = []
    self.count = 0
    self.start_time = time.time()
    self.next_time = self.start_time + 1

  def Add(self):
    self.got_nodes.append(FollowBytes(self.ctx, 'bytes'))
    # Print stats
    self.count += 1
    time_now = time.time()
    if time_now > self.next_time:
      self.next_time += 1
      self.PrintStat()

  def PrintStat(self):
    taken = time.time() - self.start_time
    print '%i templates in %.1fs; %.2fs template/sec' % (
        self.count, taken, self.count / taken)

  def Run(self, term):
    term(self.ctx, self.Add)
    self.PrintStat()
    return Time(lambda: trie.MergeMany(self.got_nodes, MergeAcceptTypes))


# Identify wildcard edges that were not present in the original
# templates.  These can occur as a result of merging multiple tries
# together.  We do this in a separate function so that the core trie
# code can be independent of trie edge types.  This is cheap to do as
# an extra pass, since the trie is not much bigger before.
#
# An alternative way to do this would be to expand out the 'XX' edges
# to list all 256 possible bytes, but the 'XX' edges are more
# convenient to handle in some cases, e.g. when enumerating all
# instructions.
#
# TODO: This is rendered unnecessary by the expanding-out done in
# TrieOfList().
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


def TrieOfBytes(bytes, tail):
  return TrieOfList(tuple(FormatByte(byte) for byte in bytes), tail)


def SandboxedJumps():
  tail = trie.MakeInterned({}, 'normal_inst')
  for reg in range(8):
    yield TrieOfBytes([0x83, 0xe0 | reg, 0xe0,  # and $~31, %reg
                       0xff, 0xe0 | reg],       # jmp *%reg
                      tail)
    yield TrieOfBytes([0x83, 0xe0 | reg, 0xe0,  # and $~31, %reg
                       0xff, 0xd0 | reg],       # call *%reg
                      tail)


def Main():
  generator = Generator()
  generator.got_nodes.extend(SandboxedJumps())
  root = generator.Run(constraint_gen.NaClEncode)
  print 'Node count before identifying extra wildcards: %i' % \
      len(trie.GetAllNodes(root))
  root = SimplifyWildcards(root)
  print 'Node count: %i' % len(trie.GetAllNodes(root))
  trie.WriteToFile('new.trie', root)


if __name__ == '__main__':
  Main()
