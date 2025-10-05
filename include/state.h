#ifndef STATE_H
#define STATE_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    uint8_t** bytes;
    int key_size;
} state_t;

void state_allocate(state_t*, int);
void state_free(state_t*);
void set_byte(state_t*, uint8_t, int, int);
uint8_t get_byte(state_t*, int, int);
int get_size(state_t*);

#endif /* STATE_H */