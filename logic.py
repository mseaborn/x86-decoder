
class Context(object):

  def __init__(self):
    self.vars = {}
    self.changes = []

  def Set(self, var, i, cont):
    if var in self.vars:
      if self.vars[var] == i:
        cont()
    else:
      def Undo():
        del self.vars[var]
      self.changes.append(Undo)
      self.vars[var] = i
      cont()

  def Choice(self):
    old_changes = self.changes
    self.changes = []
    def Restore():
      for undo in self.changes:
        undo()
      self.changes = old_changes
    return Restore


def Equal(var, i):
  def Func(ctx, cont):
    ctx.Set(var, i, cont)
  return Func

def EqualVar(var1, var2):
  def Func(ctx, cont):
    ctx.Set(var1, ctx.vars[var2], cont)
  return Func

# Note that this is non-generative: it only works if var has already
# been assigned.
def NotEqual(var, i):
  def Func(ctx, cont):
    if ctx.vars[var] != i:
      cont()
  return Func

def Apply(dest_var, func, arg_vars, *args):
  def Func(ctx, cont):
    result = func([ctx.vars[var] for var in arg_vars], *args)
    ctx.Set(dest_var, result, cont)
  return Func

def ForRange(var, upto):
  def Func(ctx, cont):
    if var in ctx.vars:
      # Fast path.
      if 0 <= ctx.vars[var] < upto:
        cont()
    else:
      for x in xrange(upto):
        restore = ctx.Choice()
        ctx.Set(var, x, cont)
        restore()
  return Func

def Conj2(term1, term2):
  def Func(ctx, cont):
    term1(ctx, lambda: term2(ctx, cont))
  return Func

def Disj2(term1, term2):
  def Func(ctx, cont):
    restore = ctx.Choice()
    term1(ctx, cont)
    restore()
    term2(ctx, cont)
  return Func

def Conj(*terms):
  return reduce(Conj2, terms)

def Disj(*terms):
  return reduce(Disj2, terms)


# Syntactic sugar.
def Switch(var, *branches):
  return Disj(*[Conj(Equal(var, x), code)
                for x, code in branches])


def GenerateAll(term, callback):
  ctx = Context()
  term(ctx, lambda: callback(ctx.vars.copy()))
  for undo in ctx.changes:
    undo()
  ctx.changes = []
  assert ctx.vars == {}

def GetAll(term):
  got = []
  GenerateAll(term, got.append)
  return got


# Test cases

def assert_eq(x, y):
  if x != y:
    raise AssertionError('%r != %r' % (x, y))

assert_eq(GetAll(Conj(ForRange('x', 2),
                      ForRange('y', 2))),
          [{'x':0, 'y':0},
           {'x':0, 'y':1},
           {'x':1, 'y':0},
           {'x':1, 'y':1}])
# Check that Equal() works on an already-assigned variable.
assert_eq(GetAll(Conj(ForRange('x', 10),
                      Equal('x', 3))),
          [{'x': 3}])
# Check that Equal() can assign.
# Check that ForRange() checks the var.
assert_eq(GetAll(Conj(Equal('x', 3),
                      ForRange('x', 10))),
          [{'x': 3}])
# Test NotEqual().
assert_eq(GetAll(Conj(ForRange('x', 3),
                      NotEqual('x', 1))),
          [{'x': 0},
           {'x': 2}])
# Test EqualVar().
assert_eq(GetAll(Conj(ForRange('x', 2),
                      ForRange('y', 2),
                      EqualVar('x', 'y'))),
          [{'x':0, 'y':0},
           {'x':1, 'y':1}])
# Test Assign().
assert_eq(GetAll(Conj(ForRange('x', 2),
                      ForRange('y', 2),
                      Apply('z', tuple, ['x', 'y']))),
          [{'x':0, 'y':0, 'z':(0,0)},
           {'x':0, 'y':1, 'z':(0,1)},
           {'x':1, 'y':0, 'z':(1,0)},
           {'x':1, 'y':1, 'z':(1,1)}])
# Test Disj().
assert_eq(GetAll(Conj(Disj(Equal('x', 'a'), Equal('x', 'b')),
                      Disj(Equal('y', 'c'), Equal('y', 'd')))),
          [{'x':'a', 'y':'c'},
           {'x':'a', 'y':'d'},
           {'x':'b', 'y':'c'},
           {'x':'b', 'y':'d'}])
