#ifndef MATHS_H
#define MATHS_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "state.h"

uint8_t multiplication(uint8_t a, uint8_t b);
void multiplication_GF128(state_t *tag, state_t *H);

#endif /* MATHS_H */