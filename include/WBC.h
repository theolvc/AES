#ifndef WBC_H
#define WBC_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "block.h"
#include "cipher.h"
#include "maths.h"

void XOR_table(uint8_t Xor[9][96][16][16]);
void composing_tables(uint32_t TBoxesTyiTables[9][16][256], uint8_t lastTbox[16][256], uint8_t* key);
void WBC_cipher(FILE* file, long blocks_number, uint32_t TBoxesTyiTables[9][16][256], uint8_t lastTbox[16][256], uint8_t Xor[9][96][16][16]);
void mixBijections(uint32_t mixInput[10][16][256], uint32_t mixOutput[9][16][256], uint32_t TBoxTyiTables[9][16][256],
                   uint8_t lastTBox[16][256]);
void WBC_cipher_v2(FILE *file, long blocks_number, uint32_t mixInput[10][16][256], uint32_t mixOutput[9][16][256], uint8_t Xor[9][96][16][16]);

#endif /* WBC_H */