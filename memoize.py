# Copyright (c) 2011 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


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
