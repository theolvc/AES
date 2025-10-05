#include "maths.h"

// Multiplication pour l'AES
uint8_t multiplication(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    while (a != 0 && b != 0) {
        if (b & 1) {  // b a un coefficient de degré 0
            result ^= a;
        }
        if (a & 0x80) {  // a un coefficient de degré 7
            a = (a << 1) ^ 0x1b;
        } else {
            a <<= 1;
        }
        b >>= 1;
    }
    return result;
}

// Xore deux à deux les octets
void XOR(uint8_t *a, uint8_t *b) {
    for (int i = 0; i < 16; i++) {
        a[i] ^= b[i];
    }
}

// Shift d'un bit vers la droite pour tous les octets
void right_shift(uint8_t *a, int i, bool add_one) {
    uint8_t last_bit = a[i] & 1UL;
    a[i] >>= 1;
    if (add_one) {
        a[i] |= 0x80;
    }
    if (i < 15) {
        right_shift(a, i + 1, (last_bit == 1));
    }
}

// Multiplication sur GF(2^128) pour GCM
void multiplication_GF128(state_t *tag, state_t *H) {
    uint8_t *V = (uint8_t *)malloc(16 * sizeof(uint8_t));
    uint8_t *Z = (uint8_t *)malloc(16 * sizeof(uint8_t));
    uint8_t R = 0xe1;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            Z[4 * i + j] = 0;
            V[4 * i + j] = get_byte(H, j, i);
        }
    }
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            for (int k = 7; k >= 0; k--) {
                uint8_t mask_tag = (1UL << k);
                uint8_t mask_V = (1UL << (7 - k));
                uint8_t bit_tag = (get_byte(tag, j, i) & mask_tag) >> k;
                uint8_t bit_V = (V[15 - 4 * i - j] & mask_V) >> (7 - k);
                if (bit_tag == 1) XOR(Z, V);
                right_shift(V, 0, false);
                if (bit_V == 1) V[0] ^= R;
            }
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            set_byte(tag, Z[4 * i + j], j, i);
        }
    }
    free(Z);
    free(V);
}