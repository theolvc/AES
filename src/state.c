#include "state.h"

void state_allocate(state_t* b, int size) {
    b->bytes = (uint8_t**)malloc(4 * sizeof(uint8_t*));
    b->key_size = size;
    if (b->bytes == NULL) {
        errx(EXIT_FAILURE, "The allocation of the bytes failed, exit");
    }
    for (int i = 0; i < 4; i++) {
        b->bytes[i] = (uint8_t*)malloc(4 * sizeof(uint8_t));
        if (b->bytes[i] == NULL) {
            state_free(b);
            errx(EXIT_FAILURE, "The allocation of the bytes failed, exit");
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            set_byte(b, 0, j, i);
        }
    }
}

void state_free(state_t* b) {
    if (b->bytes != NULL) {
        for (int i = 0; i < 4; i++) {
            free(b->bytes[i]);
        }
        free(b->bytes);
    }
}

void set_byte(state_t* b, uint8_t byte, int row, int column) { b->bytes[row][column] = byte; }

uint8_t get_byte(state_t* b, int row, int column) { return b->bytes[row][column]; }

int get_size(state_t* b) { return b->key_size; }