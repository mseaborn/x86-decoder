
all: test

clean:
	rm -fv x86_32.trie trie_table.h dfa_ncval

test: dfa_ncval
	python -u validator_test.py

dfa_ncval: dfa_ncval.c trie_table.h
	gcc -Wall -Werror -O2 -m32 dfa_ncval.c -o dfa_ncval

trie_table.h: trie_to_c.py trie.py x86_32.trie
	python trie_to_c.py

x86_32.trie: generator.py trie.py
	python generator.py
