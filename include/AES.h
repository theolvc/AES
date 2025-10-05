#ifndef AES_H
#define AES_H

#include <err.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "WBC.h"
#include "block.h"
#include "cipher.h"
#include "maths.h"
#include "state.h"

typedef enum { ECB, CBC, CFB, OFB, GCM, WBC } encoding_t;

struct Params {
    int key_size;
    uint8_t* key;
    uint8_t* expanded_key;
    bool cipher_mod;
    encoding_t encoding_mod;
    uint8_t IV[16];
    bool initialized_mod;
    int block_length;
    uint8_t tag[16];
};

#endif /* AES_H */