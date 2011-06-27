#!/bin/bash

set -eu

python trie_to_c.py
gcc -Wall -Werror -O2 -m32 dfa_ncval.c -o dfa_ncval
python -u validator_test.py
