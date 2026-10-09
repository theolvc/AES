#include "block.h"

char authorized_char[] = "0123456789ABCDEFabcdefx";

// Renvoie true si le charactère correspond à un hexadécimal ou x
bool is_authorized(char c) {
    for (int i = 0; i < 24; i++) {
        if (c == authorized_char[i]) {
            return true;
        }
    }
    return false;
}

// Renvoie la taille du texte
long text_length(FILE *file) {
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    return length;
}

// Renvoie la taille de la clé et vérifie que la clé n'a pas de caractère non autorisé
int key_length(FILE *file) {
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (length != 34 && length != 50 && length != 66) {
        errx(EXIT_FAILURE, "The key should have a length of 128, 192 or 256 bits, exit.");
    }
    return (length - 2) / 2;
}

// Récupère la clé dans le fichier
void key_parser(uint8_t *key, FILE *file) {
    char header[3];
    if (fread(header, 1, 2, file) != 2 || header[0] != '0' || header[1] != 'x') {
        errx(EXIT_FAILURE, "The key must start by 0x, exit.");
    }

    int index = 0;
    char byte_str[3];
    byte_str[2] = '\0';

    while (fread(byte_str, 1, 2, file) == 2) {
        if (!is_authorized(byte_str[0]) || !is_authorized(byte_str[1]) || byte_str[0] == 'x' || byte_str[1] == 'x') {
            errx(EXIT_FAILURE, "The key has an unauthorized character, exit.");
        }
        key[index++] = (uint8_t)strtol(byte_str, NULL, 16);
    }
}

// Récupère l'IV dans le fichier
void IV_parser(uint8_t IV[16], FILE *file) {
    char bit_value[3];
    int ch = fgetc(file);
    bit_value[0] = ch;
    ch = fgetc(file);
    bit_value[1] = ch;
    if (strcmp(bit_value, "0x") != 0) {
        errx(EXIT_FAILURE, "The IV must start by 0x, exit.");
    }
    ch = fgetc(file);
    int index = 0;
    while (ch != EOF) {
        if (!is_authorized(ch) || ch == 'x') {
            errx(EXIT_FAILURE, "The IV has an unauthorized character, exit.");
        }
        bit_value[0] = ch;
        ch = fgetc(file);
        if (!is_authorized(ch) || ch == 'x') {
            errx(EXIT_FAILURE, "The IV has an unauthorized character, exit.");
        }
        bit_value[1] = ch;
        uint8_t bit = (uint8_t)strtol(bit_value, NULL, 16);
        IV[index] = bit;
        index++;
        ch = fgetc(file);
    }
    if (index != 16) {
        errx(EXIT_FAILURE, "The IV should have a length of 128 bits, exit.");
    }
    fseek(file, 0, SEEK_SET);
}

// Xore les (block_size)-premiers octets des deux state_t
void CFB_xor(uint8_t cipher[16], uint8_t plaintext[16], int block_size) {
    for (int i = 0; i < 16; i++) {
        if (i <= block_size) {
            plaintext[i] ^= cipher[i];
        } else {
            plaintext[i] = 0;
        }        
    }
}

// Effectue l'opération de shift dans CFB
void CFB_shift(uint8_t cipher[16], uint8_t plaintext[16], int block_size) {
    for (int i = 0; i < 16 - block_size; i++) {
        cipher[i] = cipher[i + block_size];
    }
    for (int i = 16 - block_size; i < 16; i++) {
        cipher[i] = plaintext[i - (16 - block_size)];
    }
}

// Incrémente le compteur dans GCM
void increment(uint8_t IV[16], int i) {
    IV[i]++;
    if (IV[i] == 0) {
        if (i == 12) {
            errx(EXIT_FAILURE, "The text is too big to be encrypted or decrypted, exit.");
        }
        increment(IV, i - 1);
    }
}

// Récupère l'IV dans le fichier (96 bits, uniquement pour GCM)
void IV_GCM_parser(uint8_t IV[12], FILE *file) {
    char bit_value[3];
    int ch = fgetc(file);
    bit_value[0] = ch;
    ch = fgetc(file);
    bit_value[1] = ch;
    if (strcmp(bit_value, "0x") != 0) {
        errx(EXIT_FAILURE, "The IV must start by 0x, exit.");
    }
    ch = fgetc(file);
    int index = 0;
    while (ch != EOF) {
        if (!is_authorized(ch) || ch == 'x') {
            errx(EXIT_FAILURE, "The IV has an unauthorized character, exit.");
        }
        bit_value[0] = ch;
        ch = fgetc(file);
        if (!is_authorized(ch) || ch == 'x') {
            errx(EXIT_FAILURE, "The IV has an unauthorized character, exit.");
        }
        bit_value[1] = ch;
        uint8_t bit = (uint8_t)strtol(bit_value, NULL, 16);
        IV[index] = bit;
        index++;
        ch = fgetc(file);
    }
    if (index != 12) {
        errx(EXIT_FAILURE, "The IV should have a length of 96 bits, exit.");
    }
    fseek(file, 0, SEEK_SET);
}