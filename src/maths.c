#include "maths.h"

#include <string.h>

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

// Multiplication sur GF(2^128) pour GCM (NIST SP 800-38D)
void multiplication_GF128(uint8_t tag[16], const uint8_t H[16]) {
    uint8_t V[16];
    uint8_t Z[16] = {0};
    uint8_t R = 0xe1;

    memcpy(V, H, 16);

    for (int i = 0; i < 16; i++) {
        uint8_t byte = tag[i];
        for (int k = 7; k >= 0; k--) {
            if ((byte >> k) & 1) {
                for (int b = 0; b < 16; b++) {
                    Z[b] ^= V[b];
                }
            }
            uint8_t lsb = V[15] & 1;
            for (int b = 15; b > 0; b--) {
                V[b] = (V[b] >> 1) | ((V[b - 1] & 1) << 7);
            }
            V[0] >>= 1;
            if (lsb) {
                V[0] ^= R;
            }
        }
    }

    memcpy(tag, Z, 16);
}