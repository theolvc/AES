#ifndef CIPHER_H
#define CIPHER_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "maths.h"

void expansionKey(uint8_t* key, uint8_t* expanded_key, int round);
void cipher(uint8_t b[16], uint8_t* expanded_key, int round);
void decipher(uint8_t b[16], uint8_t* expanded_key, int round);

void ShiftRows(uint8_t b[16]);
uint8_t get_Sbox(uint8_t index);

#endif /* CIPHER_H */