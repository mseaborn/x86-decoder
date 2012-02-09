# Copyright (c) 2012 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import json
import unittest

import trie


class TrieTest(unittest.TestCase):

  def test_save_and_load(self):
    node = trie.MakeInterned({'foo': trie.AcceptNode,
                              'bar': trie.AcceptNode}, False)
    node2 = trie.TrieFromDict(trie.TrieToDict(node))
    self.assertEquals(node, node2)
    # Check round-tripping via JSON as well.
    node2 = trie.TrieFromDict(json.loads(json.dumps(trie.TrieToDict(node))))
    self.assertEquals(node, node2)


if __name__ == '__main__':
  unittest.main()
