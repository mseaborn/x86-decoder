/*
 * Copyright (c) 2011 The Native Client Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;


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


struct ZeroExtendState {
  int instruction_pos; /* Position of instruction as offset from bundle */
  int zeroextend_reg_before;
  int zeroextend_reg_after;
};

static int CheckZeroExtendBefore(struct ZeroExtendState *zx_state,
                                 uint32_t *mask_dest, int reg) {
  if (zx_state->zeroextend_reg_before == reg) {
    /* Mask the current instruction as not a valid jump target. */
    uint32_t bit = 1 << (zx_state->instruction_pos - 1);
    assert((*mask_dest & bit) != 0);
    *mask_dest &= ~bit;
    return 0;
  } else {
    printf("register %i not zero-extended at %x (%i)\n",
           reg, zx_state->instruction_pos, zx_state->zeroextend_reg_before);
    return 1;
  }
}

static void MarkZeroExtendAfter(struct ZeroExtendState *zx_state, int reg) {
  assert(zx_state->zeroextend_reg_after == -1);
  zx_state->zeroextend_reg_after = reg;
}

#include "trie_table.h"


static void CheckBounds(unsigned char *data, size_t data_size,
                        void *ptr, size_t inside_size) {
  assert(data <= (unsigned char *) ptr);
  assert((unsigned char *) ptr + inside_size <= data + data_size);
}

int CheckJumpTargets(uint8_t *valid_targets, uint8_t *jump_dests,
                     size_t size) {
  int i;
  for (i = 0; i < size / 32; i++) {
    uint32_t jump_dest_mask = ((uint32_t *) jump_dests)[i];
    uint32_t valid_target_mask = ((uint32_t *) valid_targets)[i];
    if ((jump_dest_mask & ~valid_target_mask) != 0) {
      printf("bad jump to around %x\n", i * sizeof(uint32_t));
      return 1;
    }
  }
  return 0;
}

int ValidateChunk(uint32_t load_addr, uint8_t *data, size_t size) {
  const int bundle_size = 32;
  const int bundle_mask = bundle_size - 1;
  assert(size % bundle_size == 0);

  int result = 0;

  uint8_t *valid_targets = BitmapAllocate(size);
  uint8_t *jump_dests = BitmapAllocate(size);

  int offset = 0;
  uint8_t *ptr = data;
  uint8_t *end = data + size;

  uint32_t *mask_dest = (uint32_t *) valid_targets;
  while (ptr < end) {
    /* Process an instruction bundle. */
    uint32_t mask = 0;
    int bundle_offset = 0;
    trie_state_t state = trie_start;
    struct ZeroExtendState zx_state;
    zx_state.instruction_pos = 0;
    zx_state.zeroextend_reg_before = -1;
    zx_state.zeroextend_reg_after = -1;
    while (bundle_offset < bundle_size) {
      state = trie_lookup(state, *ptr);
      if (state == 0) {
        printf("rejected at %x (byte 0x%02x)\n",
               load_addr + offset + bundle_offset, *ptr);
        return 1;
      }
      if (trie_label_transition(&state, &zx_state, &mask)) {
        printf("rejected at %x\n", load_addr + offset + bundle_offset);
        return 1;
      }
      ptr++;
      bundle_offset++;

      /* TODO: Don't use a nested function. */
      void RelativeJump(int32_t relative) {
        uint32_t jump_dest = offset + bundle_offset + relative;
        if ((jump_dest & bundle_mask) != 0) {
          /* Either '>' or '>=' work here since size is bundle-aligned
             and jump_dest is not. */
          if (jump_dest >= size) {
            printf("direct jump out of range: %x\n", jump_dest);
            result = 1;
          } else {
            /* We subtract 1 because the bit indexes in valid_targets
               are off by 1.  We do not need to record the starts of
               bundles as valid targets. */
            BitmapSetBit(jump_dests, jump_dest - 1);
          }
        }
        mask |= 1 << (bundle_offset - 1);
        state = trie_start;
        zx_state.instruction_pos = bundle_offset;
        zx_state.zeroextend_reg_before = zx_state.zeroextend_reg_after;
        zx_state.zeroextend_reg_after = -1;
      }

      if (trie_accepts_normal_inst(state)) {
        mask |= 1 << (bundle_offset - 1);
        state = trie_start;
        zx_state.instruction_pos = bundle_offset;
        zx_state.zeroextend_reg_before = zx_state.zeroextend_reg_after;
        zx_state.zeroextend_reg_after = -1;
      } else if (trie_accepts_jump_rel1(state)) {
        RelativeJump(((int8_t *) ptr)[-1]);
      } else if (trie_accepts_jump_rel2(state)) {
        RelativeJump(((int16_t *) ptr)[-1]);
      } else if (trie_accepts_jump_rel4(state)) {
        RelativeJump(((int32_t *) ptr)[-1]);
      } else if (trie_accepts_superinst_start(state)) {
        /* We've reached the end of a valid instruction, but it may be
           the start of a superinstruction.  Try reading more bytes to
           see if we reach an accepting state.  If we don't, we
           backtrack.
           The backtracking should not be too expensive because we
           don't expect to see the mask instruction 'and $~31, %reg'
           on its own very often. */
        int bundle_offset2 = bundle_offset;
        trie_state_t state2 = state;
        uint8_t *ptr2 = ptr;
        while (bundle_offset2 < bundle_size) {
          state2 = trie_lookup(state2, *ptr2);
          if (state2 == 0) {
            /* Backtrack early.  It is not essential to catch this
               case, but otherwise we will scan the rest of the
               bundle. */
            break;
          }
          ptr2++;
          bundle_offset2++;
          if (trie_accepts_normal_inst(state2)) {
            /* Commit to the superinstruction. */
            bundle_offset = bundle_offset2;
            ptr = ptr2;
            /* Undo any zero-extend post-condition that the first
               instruction of the superinstruction may have recorded,
               because the superinstruction overall may not have this
               post-condition. */
            zx_state.zeroextend_reg_after = -1;
            break;
          }
        }
        /* When we've reached here we have either:
            - backtracked (by reaching a reject state or by reaching the
              end of the bundle), in which case we forget
              state2/ptr2/bundle_offset2; or
            - committed to the superinstruction.
           Either way we record the end of the instruction that we reached. */
        mask |= 1 << (bundle_offset - 1);
        state = trie_start;
        zx_state.instruction_pos = bundle_offset;
        zx_state.zeroextend_reg_before = zx_state.zeroextend_reg_after;
        zx_state.zeroextend_reg_after = -1;
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

  if (CheckJumpTargets(valid_targets, jump_dests, size)) {
    return 1;
  }

  free(valid_targets);
  free(jump_dests);
  return result;
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
  int index;
  if (argc == 1) {
    printf("%s: no input files\n", argv[0]);
  }
  for (index = 1; index < argc; index++) {
    const char *filename = argv[index];
    int rc = ValidateFile(filename);
    if (rc != 0) {
      printf("file '%s' failed validation\n", filename);
      return 1;
    }
  }
  return 0;
}
