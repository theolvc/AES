#ifndef BLOC_H
#define BLOC_H

#include <string.h>

#include "cipher.h"
#include "state.h"

long text_length(FILE *file);
void file_parser(state_t **blocks, FILE *file, int key_size, long length, int block_size);
void next_block(state_t* block, FILE *file, int block_size);
void state_to_char(state_t **blocks, char *text, long blocks_number, int block_size);
void state_to_char2(state_t *block, char *text, int block_size);
int key_length(FILE *file);
void key_parser(uint8_t *key, FILE *file);
void IV_parser(uint8_t IV[16], FILE *file);
int find_block_size(long length);
void CFB_xor(state_t *cipher, state_t *plaintext, int block_size);
void CFB_shift(state_t *cipher, state_t *plaintext, int block_size);
void IV_to_state(state_t *b, uint8_t IV[16]);
void copy_state(state_t *initial, state_t *empty);
void increment(uint8_t *IV, int i);
void GCM_xor(state_t *cipher, state_t *plaintext);
void GCTR(state_t **text, uint8_t *IV, uint8_t *expanded_key, int key_size, long text_length);
void GHASH(state_t **text, state_t *tag, state_t *H, int key_size, long text_length);
void tag_to_file(state_t *tag);
void IV_GCM_parser(uint8_t IV[12], FILE *file);

#endif /* BLOC_H */