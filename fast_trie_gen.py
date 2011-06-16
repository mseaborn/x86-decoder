
import time

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


def FollowByte(ctx, var):
  if var in ctx.vars:
    return [ctx.vars[var]]
  for con in GetApplyConstraint(ctx, var, constraint_gen.CatBits):
    vals = [GetVarValues(ctx, arg) for arg in con.arg_vars]
    return [constraint_gen.CatBits(perm, *con.args)
            for perm in Permutations(vals)]
  raise AssertionError('FollowByte failed')


def FollowBytes(ctx, var):
  if var in ctx.vars:
    return ctx.vars[var]
  for con in ctx.waiting.get(var, []):
    if isinstance(con, logic.EqualVarConstraint) and con.var1 == var:
      return FollowBytes(ctx, con.var2)
  for con in GetApplyConstraint(ctx, var, constraint_gen.PrependByte):
    return [map(FormatByte, FollowByte(ctx, con.arg_vars[0]))] + \
            FollowBytes(ctx, con.arg_vars[1])
  raise AssertionError('FollowBytes failed')


def TrieOfList(bytes):
  node = trie.AcceptNode
  for item in reversed(bytes):
    children = {}
    if isinstance(item, list):
      for byte in item:
        children[byte] = node
    else:
      children[item] = node
    node = trie.Trie()
    node.children = children
  return node


class Generator(object):

  def __init__(self):
    self.ctx = logic.Context()
    self.root = trie.EmptyNode
    self.count = 0
    self.start_time = time.time()
    self.next_time = self.start_time + 1

  def Add(self):
    bytes = FollowBytes(self.ctx, 'bytes')
    self.root = trie.Merge(self.root, TrieOfList(bytes))
    # Print stats
    self.count += 1
    time_now = time.time()
    if time_now > self.next_time:
      taken = time_now - self.start_time
      print '%i templates in %.1fs; %.2fs template/sec' % (
          self.count, taken, self.count / taken)
      self.next_time += 1

  def Run(self, term):
    term(self.ctx, self.Add)


def Main():
  generator = Generator()
  generator.Run(constraint_gen.Encode)
  trie.WriteToFile('new.trie', generator.root)


if __name__ == '__main__':
  Main()
