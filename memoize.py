

NOT_FOUND = object()


def Memoize(func):
  cache = {}
  def Wrapper(*args):
    value = cache.get(args, NOT_FOUND)
    if value is NOT_FOUND:
      value = func(*args)
      cache[args] = value
    return value
  return Wrapper
