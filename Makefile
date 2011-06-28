
all: test

clean:
	rm -fv new.trie trie_table.h dfa_ncval

test: dfa_ncval
	python -u validator_test.py

dfa_ncval: dfa_ncval.c trie_table.h
	gcc -Wall -Werror -O2 -m32 dfa_ncval.c -o dfa_ncval

trie_table.h: trie_to_c.py trie.py new.trie
	python trie_to_c.py

new.trie: fast_trie_gen.py constraint_gen.py logic.py trie.py
	python fast_trie_gen.py
