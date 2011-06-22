
#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "trie_table.h"


typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;


static const int kBitsPerByte = 8;

static inline uint8_t *BitmapAllocate(uint32_t indexes) {
  uint32_t byte_count = (indexes + kBitsPerByte - 1) / kBitsPerByte;
  uint8_t *bitmap = malloc(byte_count);
  if (bitmap != NULL) {
    memset(bitmap, 0, byte_count);
  }
  return bitmap;
}

static inline int BitmapIsBitSet(uint8_t *bitmap, uint32_t index) {
  return (bitmap[index / kBitsPerByte] & (1 << (index % kBitsPerByte))) != 0;
}

static inline void BitmapSetBit(uint8_t *bitmap, uint32_t index) {
  bitmap[index / kBitsPerByte] |= 1 << (index % kBitsPerByte);
}


static void CheckBounds(unsigned char *data, size_t data_size,
                        void *ptr, size_t inside_size) {
  assert(data <= (unsigned char *) ptr);
  assert((unsigned char *) ptr + inside_size <= data + data_size);
}

int ValidateChunk(uint32_t load_addr, uint8_t *data, size_t size) {
  assert(size % 32 == 0);

  uint8_t *valid_targets = BitmapAllocate(size);

  int offset = 0;
  uint8_t *ptr = data;
  uint8_t *end = data + size;

  uint32_t *mask_dest = (uint32_t *) valid_targets;
  while (ptr < end) {
    /* Process an instruction bundle. */
    uint32_t mask = 0;
    int i;
    int state = trie_start;
    for (i = 0; i < 32; i++) {
      state = trie_table[state][*ptr];
      if (state == 0) {
        printf("rejected at %x (byte 0x%02x)\n", load_addr + offset + i, *ptr);
        return 1;
      }
      ptr++;
      if (trie_accepts(state)) {
        mask |= 1 << i;
        state = trie_start;
      }
    }
    *mask_dest++ = mask;
    offset += 32;
    if (state != trie_start) {
      printf("instruction overlaps bundle boundary at %x\n",
             load_addr + offset);
      return 1;
    }
  }

  free(valid_targets);
  return 0;
}

void ReadFile(const char *filename, uint8_t **result, size_t *result_size) {
  FILE *fp;
  uint8_t *data;
  size_t file_size;
  size_t got;

  fp = fopen(filename, "rb");
  if (fp == NULL) {
    fprintf(stderr, "Failed to open input file: %s\n", filename);
    exit(1);
  }
  /* Find the file size. */
  fseek(fp, 0, SEEK_END);
  file_size = ftell(fp);
  data = malloc(file_size);
  if (data == NULL) {
    fprintf(stderr, "Unable to create memory image of input file: %s\n",
            filename);
    exit(1);
  }
  fseek(fp, 0, SEEK_SET);
  got = fread(data, 1, file_size, fp);
  if (got != file_size) {
    fprintf(stderr, "Unable to read data from input file: %s\n",
            filename);
    exit(1);
  }
  fclose(fp);

  *result = data;
  *result_size = file_size;
}

int ValidateFile(const char *filename) {
  size_t data_size;
  uint8_t *data;
  ReadFile(filename, &data, &data_size);

  Elf_Ehdr *header;
  int index;

  header = (Elf_Ehdr *) data;
  CheckBounds(data, data_size, header, sizeof(*header));
  assert(memcmp(header->e_ident, ELFMAG, strlen(ELFMAG)) == 0);

  for (index = 0; index < header->e_shnum; index++) {
    Elf_Shdr *section = (Elf_Shdr *) (data + header->e_shoff +
                                      header->e_shentsize * index);
    CheckBounds(data, data_size, section, sizeof(*section));

    if ((section->sh_flags & SHF_EXECINSTR) != 0) {
      CheckBounds(data, data_size,
                  data + section->sh_offset, section->sh_size);
      int rc = ValidateChunk(section->sh_addr,
                             data + section->sh_offset, section->sh_size);
      if (rc != 0) {
        return rc;
      }
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  assert(argc == 2);
  return ValidateFile(argv[1]);
}
