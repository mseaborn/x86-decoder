#!/bin/bash

set -eu

python generator.py | sort > out_movs_gen
grep ^89 patterns | sort > out_movs_infer
diff -u out_movs_{infer,gen}
