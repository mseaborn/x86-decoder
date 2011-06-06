
class Context(object):

  def __init__(self):
    self.vars = {}
    self.changes = []
    self.waiting = {}

  # Tries to set var to i.
  # Returns True if successful.
  # Returns False if this produced a conflict.
  def TrySet(self, var, i):
    if var in self.vars:
      return self.vars[var] == i
    else:
      def Undo():
        del self.vars[var]
      self.changes.append(Undo)
      self.vars[var] = i
      for run_constraint in self.waiting.get(var, []):
        if not run_constraint():
          return False
      return True

  def Set(self, var, i, cont):
    if self.TrySet(var, i):
      cont()

  def AddWaiter(self, var, func):
    self.waiting.setdefault(var, []).append(func)
    def Undo():
      self.waiting[var].remove(func)
    self.changes.append(Undo)

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

# This could be implemented in terms of Apply().
def EqualVar(var1, var2):
  def Func(ctx, cont):
    # Fast paths first.
    if var1 in ctx.vars:
      ctx.Set(var2, ctx.vars[var1], cont)
    elif var2 in ctx.vars:
      ctx.Set(var1, ctx.vars[var2], cont)
    else:
      def RunConstraint():
        if var1 in ctx.vars:
          return ctx.TrySet(var2, ctx.vars[var1])
        elif var2 in ctx.vars:
          return ctx.TrySet(var1, ctx.vars[var2])
        return True
      ctx.AddWaiter(var1, RunConstraint)
      ctx.AddWaiter(var2, RunConstraint)
      cont()
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
    # Fast paths first.
    # These duplicate a chunk of code, unfortunately.
    if all(var in ctx.vars for var in arg_vars):
      result = func([ctx.vars[var] for var in arg_vars], *args)
      ctx.Set(dest_var, result, cont)
    elif dest_var in ctx.vars and hasattr(func, 'rev'):
      values = func.rev(ctx.vars[dest_var], *args)
      if values is None:
        return
      assert len(values) == len(arg_vars)
      for var, x in zip(arg_vars, values):
        if not ctx.TrySet(var, x):
          return
      cont()
    else:
      def RunConstraint():
        if all(var in ctx.vars for var in arg_vars):
          result = func([ctx.vars[var] for var in arg_vars], *args)
          return ctx.TrySet(dest_var, result)
        elif dest_var in ctx.vars and hasattr(func, 'rev'):
          values = func.rev(ctx.vars[dest_var], *args)
          if values is None:
            return False
          assert len(values) == len(arg_vars)
          for var, x in zip(arg_vars, values):
            if not ctx.TrySet(var, x):
              return False
        return True
      for var in [dest_var] + arg_vars:
        ctx.AddWaiter(var, RunConstraint)
      cont()
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
  assert ctx.vars == {}, ctx.vars
  for var, waiters in ctx.waiting.iteritems():
    assert waiters == [], var

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
# Check that EqualVar() works when the vars are not set yet.
assert_eq(GetAll(Conj(EqualVar('x', 'y'),
                      Equal('x', 123))),
          [{'x':123, 'y':123}])
assert_eq(GetAll(Conj(EqualVar('x', 'y'),
                      Equal('y', 123))),
          [{'x':123, 'y':123}])

def Tuple(args):
  return tuple(args)
def TupleRev(arg):
  return arg
Tuple.rev = TupleRev

# Test Assign().
assert_eq(GetAll(Conj(ForRange('x', 2),
                      ForRange('y', 2),
                      Apply('z', tuple, ['x', 'y']))),
          [{'x':0, 'y':0, 'z':(0,0)},
           {'x':0, 'y':1, 'z':(0,1)},
           {'x':1, 'y':0, 'z':(1,0)},
           {'x':1, 'y':1, 'z':(1,1)}])
# Check that Assign() works before the arguments are set.
# It should store a constraint.
assert_eq(GetAll(Conj(Apply('z', tuple, ['x', 'y']),
                      Equal('x', 'foo'),
                      Equal('y', 'bar'))),
          [{'x':'foo', 'y':'bar', 'z':('foo', 'bar')}])
# Check that Assign() works in reverse.
assert_eq(GetAll(Conj(Equal('z', ('foo', 'bar')),
                      Apply('z', Tuple, ['x', 'y']))),
          [{'x':'foo', 'y':'bar', 'z':('foo', 'bar')}])
assert_eq(GetAll(Conj(Apply('z', Tuple, ['x', 'y']),
                      Equal('z', ('foo', 'bar')))),
          [{'x':'foo', 'y':'bar', 'z':('foo', 'bar')}])

def TestFunc(args):
  raise AssertionError()
def TestFuncRev(arg):
  return None
TestFunc.rev = TestFuncRev

# Reversing a function is allowed to fail.
assert_eq(GetAll(Conj(Apply('z', TestFunc, ['x']),
                      Equal('z', 123))),
          [])
assert_eq(GetAll(Conj(Equal('z', 123),
                      Apply('z', TestFunc, ['x']))),
          [])

# Test Disj().
assert_eq(GetAll(Conj(Disj(Equal('x', 'a'), Equal('x', 'b')),
                      Disj(Equal('y', 'c'), Equal('y', 'd')))),
          [{'x':'a', 'y':'c'},
           {'x':'a', 'y':'d'},
           {'x':'b', 'y':'c'},
           {'x':'b', 'y':'d'}])
