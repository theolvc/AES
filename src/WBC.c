#include "WBC.h"
#include "bijection.c"

// Create the T-Boxes that will store the AddRoundKey and the SubBytes steps
void T_box(uint8_t* key, uint8_t TBox[10][16][256]) {
    uint8_t temp[176]; 
    expansionKey(key, temp, 10);
    uint8_t expanded_key[11][16];
    // Store the expanded_key in a 11x16 array to be easier to transfer into my own state_t type
    for (int i = 0; i < 11; i++) {
        for (int j = 0; j < 16; j++) {
            expanded_key[i][j] = temp[16 * i + j];
        }
    }
    uint8_t state_key[11][16];

    for (int i = 0; i < 10; i++) {
        memcpy(state_key[i], expanded_key[i], 16);
        ShiftRows(state_key[i]);
    }
    memcpy(state_key[10], expanded_key[10], 16);

    // Apply the value for each T-box
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                for (int l = 0; l < 256; l++) {
                    TBox[i][4 * j + k][l] = get_Sbox(l ^ state_key[i][4 * j + k]);
                }
            }
        }
    }
    for (int j = 0; j < 4; j++) {
        for (int k = 0; k < 4; k++) {
            for (int l = 0; l < 256; l++) {
                TBox[9][4 * j + k][l] = get_Sbox(l ^ state_key[9][4 * j + k]) ^ state_key[10][4 * j + k];
            }
        }
    }
}

// Create the Tyi Tables
void Tyi_tables(uint32_t TyiTables[4][256]) {
    uint8_t vec[4][4] = {{2, 1, 1, 3}, {3, 2, 1, 1}, {1, 3, 2, 1}, {1, 1, 3, 2}};
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 256; j++) {
            uint8_t part1 = multiplication(j, vec[i][0]);
            uint8_t part2 = multiplication(j, vec[i][1]);
            uint8_t part3 = multiplication(j, vec[i][2]);
            uint8_t part4 = multiplication(j, vec[i][3]);
            uint32_t result = (part1 << 24) | (part2 << 16) | (part3 << 8) | part4;
            TyiTables[i][j] = result;
        }
    }
}

// Create the XOR Tables
void XOR_table(uint8_t Xor[9][96][16][16]) {
    for (int r = 0; r < 9; r++) {
        for (int k = 0; k < 96; k++) {
            for (int i = 0; i < 16; i++) {
                for (int j = 0; j < 16; j++) {
                    if (r == 0 && k == 0) {
                        Xor[r][k][i][j] = i ^ j;
                    } else {
                        Xor[r][k][i][j] = Xor[0][0][i][j];  // Other tables are just a copy of the first table
                    }
                }
            }
        }
    }
}

// Create the composing Tables
void composing_tables(uint32_t TBoxesTyiTables[9][16][256], uint8_t lastTbox[16][256], uint8_t* key) {
    uint8_t Tbox[10][16][256];
    T_box(key, Tbox);
    uint32_t TyiTables[4][256];
    Tyi_tables(TyiTables);
    for (int r = 0; r < 9; r++) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 256; j++) {
                TBoxesTyiTables[r][i][j] = TyiTables[i % 4][Tbox[r][i][j]];
            }
        }
    }
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 256; j++) {
            lastTbox[i][j] = Tbox[9][i][j];
        }
    }
}

// XOR a and b 4-bit by 4-bit using the XOR Table
uint32_t Xor4by4(uint8_t Xor[16][16], uint32_t a, uint32_t b) {
    uint8_t part1 = Xor[(a >> 28) & 0xF][(b >> 28) & 0xF];
    uint8_t part2 = Xor[(a >> 24) & 0xF][(b >> 24) & 0xF];
    uint8_t part3 = Xor[(a >> 20) & 0xF][(b >> 20) & 0xF];
    uint8_t part4 = Xor[(a >> 16) & 0xF][(b >> 16) & 0xF];
    uint8_t part5 = Xor[(a >> 12) & 0xF][(b >> 12) & 0xF];
    uint8_t part6 = Xor[(a >> 8) & 0xF][(b >> 8) & 0xF];
    uint8_t part7 = Xor[(a >> 4) & 0xF][(b >> 4) & 0xF];
    uint8_t part8 = Xor[a & 0xF][b & 0xF];
    uint32_t result = (part1 << 28) | (part2 << 24) | (part3 << 20) | (part4 << 16) | (part5 << 12) | (part6 << 8) |
                      (part7 << 4) | part8;
    return result;
}

// First version of the ciphering in the White-Box AES, without encoding the tables
void WBC_cipher(FILE* file, long blocks_number, uint32_t TBoxesTyiTables[9][16][256], uint8_t lastTbox[16][256], uint8_t Xor[9][96][16][16]) {
    uint32_t TBoxTyiResult[16];
    uint32_t firstXor[8];
    uint32_t secondXor[4];
    uint8_t block[16];
    char texte[16];

    FILE *output_file = fopen("cipher.txt", "w+");
    if (output_file == NULL) {
        errx(EXIT_FAILURE, "Couldn't create cipher.txt, exit.");
    }
    bool padding = (text_length(file) % 16 != 0);

    // Cipher all blocks
    for (long i = 0; i < blocks_number; i++) {
        if (i < blocks_number - 1) {
            fread(block, 1, 16, file);
        } else {
            if (!padding) {
                memset(block, 16, 16);
            } else {
                size_t read_bytes = fread(block, 1, 16, file);
                for (size_t j = read_bytes; j < 16; j++) {
                    block[j] = 16 - read_bytes;
                }
            }
        }
        // Cipher one block
        for (int r = 0; r < 9; r++) {
            ShiftRows(block);
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    TBoxTyiResult[4 * j + k] = TBoxesTyiTables[r][4 * j + k][block[4 * j + k]];  // Gets the result in the composing table
                }
            }
            // XOR the results 2 by 2
            for (int j = 0; j < 8; j++) {
                firstXor[j] = Xor4by4(Xor[r][0], TBoxTyiResult[2 * j], TBoxTyiResult[2 * j + 1]);
            }
            // Again XOR the new result 2 by 2
            for (int j = 0; j < 4; j++) {
                secondXor[j] = Xor4by4(Xor[r][0], firstXor[2 * j], firstXor[2 * j + 1]);
            }
            // secondXor now contains the cipher state (32-bit by 32-bit), we change the value of the state
            for (int j = 0; j < 4; j++) {
                block[4 * j] = (secondXor[j] >> 24) & 0xFF;
                block[4 * j + 1] = (secondXor[j] >> 16) & 0xFF;
                block[4 * j + 2] = (secondXor[j] >> 8) & 0xFF;
                block[4 * j + 3] = secondXor[j] & 0xFF;
            }
        }
        // Last round
        ShiftRows(block);
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                block[4 * j + k] = lastTbox[4 * j + k][block[4 * j + k]];
            }
        }
        memcpy(texte, block, 16);
        fwrite(texte, 1, 16, output_file);
    }
}

// Multiply a matrix 8x8-bit with an 8-bit integer
uint8_t multMatrix8(uint8_t matrix[8][8], uint8_t x) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 8; j++) {
            bit ^= matrix[i][j] & (x >> (7 - j) & 1);
        }
        result = result | (bit << (7 - i));
    }
    return result;
}

// Multiply a matrix 32x32-bit with a 32-bit integer
uint32_t multMatrix32(uint8_t matrix[32][32], uint32_t x) {
    uint32_t result = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t bit = 0;
        for (int j = 0; j < 32; j++) {
            bit ^= matrix[i][j] & (x >> (31 - j) & 1);
        }
        result = result | (bit << (31 - i));
    }
    return result;
}

// Encode the composing Tables, giving mixInput and his "inverse" mixOutput
void mixBijections(uint32_t mixInput[10][16][256], uint32_t mixOutput[9][16][256], uint32_t TBoxTyiTables[9][16][256],
                   uint8_t lastTBox[16][256]) {
    // Compute mixInput values
    // We apply the inverse of 8x8 matrix then the composing Tables
    for (int r = 0; r < 10; r++) {
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 256; j++) {
                if (r == 0) {
                    mixInput[r][i][j] = TBoxTyiTables[r][i][j];  // No input encoding for the first round
                } else if (r == 9) {
                    mixInput[r][i][j] = lastTBox[i][multMatrix8(InvMat8[r - 1][i], j)];
                } else {
                    mixInput[r][i][j] = TBoxTyiTables[r][i][multMatrix8(InvMat8[r - 1][i], j)];
                }
            }
        }
    }
    // Then we apply the 32x32 matrix
    for (int r = 0; r < 9; r++) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                mixInput[r][4 * i][j] = multMatrix32(Mat32[r][i], mixInput[r][4 * i][j]);
                mixInput[r][4 * i + 1][j] = multMatrix32(Mat32[r][i], mixInput[r][4 * i + 1][j]);
                mixInput[r][4 * i + 2][j] = multMatrix32(Mat32[r][i], mixInput[r][4 * i + 2][j]);
                mixInput[r][4 * i + 3][j] = multMatrix32(Mat32[r][i], mixInput[r][4 * i + 3][j]);
            }
        }
    }

    // Computing mixOutput values
    // We apply the inverse of 32x32 matrix
    for (int r = 0; r < 9; r++) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                mixOutput[r][4 * i][j] = multMatrix32(InvMat32[r][i], j << 24);
                mixOutput[r][4 * i + 1][j] = multMatrix32(InvMat32[r][i], j << 16);
                mixOutput[r][4 * i + 2][j] = multMatrix32(InvMat32[r][i], j << 8);
                mixOutput[r][4 * i + 3][j] = multMatrix32(InvMat32[r][i], j);
            }
        }
    }
    // We apply the next 8x8 matrix
    // Note that the index of the next matrix will be shifted because of ShiftRows
    int index_ShiftRows[4][4] = {{0, 13, 10, 7}, {4, 1, 14, 11}, {8, 5, 2, 15}, {12, 9, 6, 3}};
    for (int r = 0; r < 9; r++) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 256; j++) {
                mixOutput[r][4 * i][j] =
                    (multMatrix8(Mat8[r][index_ShiftRows[i][0]], (mixOutput[r][4 * i][j] >> 24) & 0xFF) << 24) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][1]], (mixOutput[r][4 * i][j] >> 16) & 0xFF) << 16) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][2]], (mixOutput[r][4 * i][j] >> 8) & 0xFF) << 8) |
                    multMatrix8(Mat8[r][index_ShiftRows[i][3]], mixOutput[r][4 * i][j] & 0xFF);
                mixOutput[r][4 * i + 1][j] =
                    (multMatrix8(Mat8[r][index_ShiftRows[i][0]], (mixOutput[r][4 * i + 1][j] >> 24) & 0xFF) << 24) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][1]], (mixOutput[r][4 * i + 1][j] >> 16) & 0xFF) << 16) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][2]], (mixOutput[r][4 * i + 1][j] >> 8) & 0xFF) << 8) |
                    multMatrix8(Mat8[r][index_ShiftRows[i][3]], mixOutput[r][4 * i + 1][j] & 0xFF);
                mixOutput[r][4 * i + 2][j] =
                    (multMatrix8(Mat8[r][index_ShiftRows[i][0]], (mixOutput[r][4 * i + 2][j] >> 24) & 0xFF) << 24) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][1]], (mixOutput[r][4 * i + 2][j] >> 16) & 0xFF) << 16) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][2]], (mixOutput[r][4 * i + 2][j] >> 8) & 0xFF) << 8) |
                    multMatrix8(Mat8[r][index_ShiftRows[i][3]], mixOutput[r][4 * i + 2][j] & 0xFF);
                mixOutput[r][4 * i + 3][j] =
                    (multMatrix8(Mat8[r][index_ShiftRows[i][0]], (mixOutput[r][4 * i + 3][j] >> 24) & 0xFF) << 24) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][1]], (mixOutput[r][4 * i + 3][j] >> 16) & 0xFF) << 16) |
                    (multMatrix8(Mat8[r][index_ShiftRows[i][2]], (mixOutput[r][4 * i + 3][j] >> 8) & 0xFF) << 8) |
                    multMatrix8(Mat8[r][index_ShiftRows[i][3]], mixOutput[r][4 * i + 3][j] & 0xFF);
            }
        }
    }
}

// Second version of the ciphering in the White-Box AES, with now the encoded tables
// NB : The XOR Tables are not encoded and should be encoded for better security, right now the tables are all the same
void WBC_cipher_v2(FILE *file, long blocks_number, uint32_t mixInput[10][16][256], uint32_t mixOutput[9][16][256],
                   uint8_t Xor[9][96][16][16]) {
    // The first part is the same as the first version
    uint32_t TBoxTyiResult[16];
    uint32_t firstXor[8];
    uint32_t secondXor[4];
    uint8_t block[16];
    char texte[16];

    FILE *output_file = fopen("cipher.txt", "w+");
    if (output_file == NULL) {
        errx(EXIT_FAILURE, "Couldn't create cipher.txt, exit.");
    }
    bool padding = (text_length(file) % 16 != 0);

    // Cipher all blocks
    for (long i = 0; i < blocks_number; i++) {
        if (i < blocks_number - 1) {
            fread(block, 1, 16, file);
        } else {
            if (!padding) {
                memset(block, 16, 16);
            } else {
                size_t read_bytes = fread(block, 1, 16, file);
                for (size_t j = read_bytes; j < 16; j++) {
                    block[j] = 16 - read_bytes;
                }
            }
        }
        // Cipher one block
        for (int r = 0; r < 9; r++) {
            ShiftRows(block);
            // Gets the result in the mixInput table
            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    TBoxTyiResult[4 * j + k] = mixInput[r][4 * j + k][block[4 * j + k]];
                }
            }
            // XOR the results 2 by 2
            for (int j = 0; j < 8; j++) {
                firstXor[j] = Xor4by4(Xor[r][0], TBoxTyiResult[2 * j], TBoxTyiResult[2 * j + 1]);
            }
            // Again XOR the new results 2 by 2
            for (int j = 0; j < 4; j++) {
                secondXor[j] = Xor4by4(Xor[r][0], firstXor[2 * j], firstXor[2 * j + 1]);
            }
            // We put the results in the first array to then apply mixOutput
            for (int j = 0; j < 4; j++) {
                TBoxTyiResult[4 * j] = (secondXor[j] >> 24) & 0xFF;
                TBoxTyiResult[4 * j + 1] = (secondXor[j] >> 16) & 0xFF;
                TBoxTyiResult[4 * j + 2] = (secondXor[j] >> 8) & 0xFF;
                TBoxTyiResult[4 * j + 3] = secondXor[j] & 0xFF;
            }
            // Gets the result in mixOutput
            for (int j = 0; j < 16; j++) {
                TBoxTyiResult[j] = mixOutput[r][j][TBoxTyiResult[j]];
            }
            // XOR the results 2 by 2
            for (int j = 0; j < 8; j++) {
                firstXor[j] = Xor4by4(Xor[r][0], TBoxTyiResult[2 * j], TBoxTyiResult[2 * j + 1]);
            }
            // XOR the results 2 by 2
            for (int j = 0; j < 4; j++) {
                secondXor[j] = Xor4by4(Xor[r][0], firstXor[2 * j], firstXor[2 * j + 1]);
            }
            // Now secondXor contains the cipher state (32-bit by 32-bit), we change the value of the state
            for (int j = 0; j < 4; j++) {
                block[4 * j] = (secondXor[j] >> 24) & 0xFF;
                block[4 * j + 1] = (secondXor[j] >> 16) & 0xFF;
                block[4 * j + 2] = (secondXor[j] >> 8) & 0xFF;
                block[4 * j + 3] = secondXor[j] & 0xFF;
            }
        }
        // Last round
        ShiftRows(block);
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                block[4 * j + k] = mixInput[9][4 * j + k][block[4 * j + k]];
                // No output encoding for the last round
            }
        }
        memcpy(texte, block, 16);
        fwrite(texte, 1, 16, output_file);
    }
}