#ifndef BLOC_H
#define BLOC_H

#include <string.h>

#include "cipher.h"

long text_length(FILE *file);
int key_length(FILE *file);
void key_parser(uint8_t *key, FILE *file);
void IV_parser(uint8_t IV[16], FILE *file);
void CFB_xor(uint8_t cipher[16], uint8_t plaintext[16], int block_size);
void CFB_shift(uint8_t cipher[16], uint8_t plaintext[16], int block_size);
void increment(uint8_t IV[16], int i);
void IV_GCM_parser(uint8_t IV[12], FILE *file);

#endif /* BLOC_H */