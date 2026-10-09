#ifndef MATHS_H
#define MATHS_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t multiplication(uint8_t a, uint8_t b);
void multiplication_GF128(uint8_t tag[16], const uint8_t H[16]);

#endif /* MATHS_H */