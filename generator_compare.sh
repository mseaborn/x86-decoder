#!/bin/bash

set -eu

python generator.py > out_movs_gen
grep -E '^(89|8b|c7)' patterns | sort > out_movs_infer
diff -u out_movs_{infer,gen}
