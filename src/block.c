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

// Renvoie la ligne où se termine le state_t en fonction de la taille du bloc
int find_row(int size) { return (size - 1) % 4; }

// Renvoie la colonne où se termine le state_t en fonction de la taille du bloc
int find_column(int size) { return (size - 1) / 4; }

// Sépare le texte dans file en plusieurs blocs de 128 bits
void file_parser(state_t **blocks, FILE *file, int key_size, long length, int block_size) {
    int space = (block_size - (length % block_size)) % block_size;
    char *text = (char *)malloc((length + space) * sizeof(char));
    int ch = fgetc(file);
    long current_char = 0;
    while (ch != EOF) {
        text[current_char] = ch;
        current_char++;
        ch = fgetc(file);
    }
    for (int i = 0; i < space; i++) {
        text[current_char] = ' ';
        current_char++;
    }
    long blocks_number = (length + space) / block_size;
    int row = find_row(block_size);
    int column = find_column(block_size);
    for (long i = 0; i < blocks_number; i++) {
        blocks[i] = (state_t *)malloc(sizeof(state_t));
        if (blocks[i] == NULL) {
            for (long j = 0; j < i; j++) {
                state_free(blocks[j]);
                free(blocks[j]);
            }
            free(blocks);
            errx(EXIT_FAILURE, "The allocation of the blocs failed, exit");
        }
        state_allocate(blocks[i], key_size);
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                if ((j == column && k <= row) || j < column) {
                    set_byte(blocks[i], (uint8_t)text[block_size * i + 4 * j + k], k, j);
                }
            }
        }
    }
    free(text);
}

void next_block(state_t* block, FILE *file, int block_size){
    char *text = (char *)malloc(block_size * sizeof(char));
    int ch = fgetc(file);
    for (int i=0; i<block_size; i++){
        if (ch == EOF){
            text[i]=' ';
        }
        else {
            text[i]=ch;
            ch=fgetc(file);
        }
    }
    int row = find_row(block_size);
    int column = find_column(block_size);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            if ((i == column && j <= row) || i < column) {
                set_byte(block, (uint8_t)text[4 * i + j], j, i);
            }
        }
    }
    free(text);
}

// Transforme le state_t en char
void state_to_char(state_t **blocks, char *text, long blocks_number, int block_size) {
    int row = find_row(block_size);
    int column = find_column(block_size);
    for (long i = 0; i < blocks_number; i++) {
        for (int j = 0; j < 4; j++) {
            for (int k = 0; k < 4; k++) {
                if ((j == column && k <= row) || j < column) {
                    text[block_size * i + 4 * j + k] = (char)get_byte(blocks[i], k, j);
                }
            }
        }
    }
}

void state_to_char2(state_t *block, char *text, int block_size) {
    int row = find_row(block_size);
    int column = find_column(block_size);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            if ((i == column && j <= row) || i < column) {
                text[4 * i + j] = (char)get_byte(block, j, i);
            }
        }
    }
}

// Renvoie la taille de la clé et vérifie que la clé n'a pas de caractère non autorisé
int key_length(FILE *file) {
    int counter = 0;
    int ch = fgetc(file);
    while (ch != EOF) {
        if (!is_authorized(ch)) {
            errx(EXIT_FAILURE, "The key has an unauthorized character, exit.");
        }
        counter++;
        ch = fgetc(file);
    }
    if (counter != 34 && counter != 50 && counter != 66) {
        errx(EXIT_FAILURE, "The key should have a length of 128, 192 or 256 bits, exit.");
    }
    fseek(file, 0, SEEK_SET);
    return (counter - 2) / 2;
}

// Récupère la clé dans le fichier
void key_parser(uint8_t *key, FILE *file) {
    char bit_value[3];
    int ch = fgetc(file);
    bit_value[0] = ch;
    ch = fgetc(file);
    bit_value[1] = ch;
    if (strcmp(bit_value, "0x") != 0) {
        errx(EXIT_FAILURE, "The key must start by 0x, exit.");
    }
    ch = fgetc(file);
    int index = 0;
    while (ch != EOF) {
        if (ch == 'x') {
            errx(EXIT_FAILURE, "x is not a valid character for hexadecimal, exit.");
        }
        bit_value[0] = ch;
        ch = fgetc(file);
        if (ch == 'x') {
            errx(EXIT_FAILURE, "x is not a valid character for hexadecimal, exit.");
        }
        bit_value[1] = ch;
        uint8_t bit = (uint8_t)strtol(bit_value, NULL, 16);
        key[index] = bit;
        index++;
        ch = fgetc(file);
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

// Trouve la plus grande taille de bloc <= 16 octets, tel que aucun padding ne soit nécessaire
int find_block_size(long length) {
    for (int i = 16; i > 0; i--) {
        if (length % i == 0) {
            return i;
        }
    }
    return 1;
}

// Change le type de l'IV en state_t
void IV_to_state(state_t *b, uint8_t IV[16]) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            set_byte(b, IV[4 * i + j], j, i);
        }
    }
}

// Copie un state_t dans un deuxième, sans changer le state_t initial
void copy_state(state_t *initial, state_t *empty) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            set_byte(empty, get_byte(initial, j, i), j, i);
        }
    }
}

// Xore les (block_size)-premiers octets des deux state_t
void CFB_xor(state_t *cipher, state_t *plaintext, int block_size) {
    int row = find_row(block_size);
    int column = find_column(block_size);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            if ((i == column && j <= row) || i < column) {
                set_byte(plaintext, get_byte(cipher, j, i) ^ get_byte(plaintext, j, i), j, i);
            } else {
                set_byte(plaintext, 0, j, i);
            }
        }
    }
}

// Effectue l'opération de shift dans CFB
void CFB_shift(state_t *cipher, state_t *plaintext, int block_size) {
    int row = find_row(block_size) + 1;
    int column = find_column(block_size);
    if (row == 4) {
        row = 0;
        column++;
    }
    bool need_break = false;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            if (column == 4) {
                need_break = true;
                break;
            }
            set_byte(cipher, get_byte(cipher, row, column), j, i);
            row++;
            if (row == 4) {
                row = 0;
                column++;
            }
        }
        if (need_break) {
            break;
        }
    }
    row = (16 - block_size) % 4;
    column = (16 - block_size) / 4;
    need_break = false;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            if (column == 4) {
                need_break = true;
                break;
            }
            set_byte(cipher, get_byte(plaintext, j, i), row, column);
            row++;
            if (row == 4) {
                row = 0;
                column++;
            }
        }
        if (need_break) {
            break;
        }
    }
}

// Incrémente le compteur dans GCM
void increment(uint8_t *IV, int i) {
    IV[i]++;
    if (IV[i] == 0) {
        if (i == 12) {
            errx(EXIT_FAILURE, "The text is too big to be encrypted or decrypted, exit.");
        }
        increment(IV, i - 1);
    }
}

// Xore les deux states
void GCM_xor(state_t *cipher, state_t *plaintext) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            set_byte(plaintext, get_byte(cipher, j, i) ^ get_byte(plaintext, j, i), j, i);
        }
    }
}

// Chiffre le texte avec GCM
void GCTR(state_t **text, uint8_t *IV, uint8_t *expanded_key, int key_size, long text_length) {
    long number_blocks = text_length / 16;
    int last_block_length = text_length % 16;
    if (last_block_length != 0) {
        number_blocks++;
    }
    state_t *cipher_state = (state_t *)malloc(sizeof(state_t));
    state_allocate(cipher_state, key_size);
    IV_to_state(cipher_state, IV);
    for (long i = 0; i < number_blocks - 1; i++) {
        cipher(cipher_state, expanded_key);
        GCM_xor(cipher_state, text[i]);
        increment(IV, 15);
        IV_to_state(cipher_state, IV);
    }
    cipher(cipher_state, expanded_key);
    if (last_block_length == 0) {
        GCM_xor(cipher_state, text[number_blocks - 1]);
    } else {
        CFB_xor(cipher_state, text[number_blocks - 1], last_block_length);
    }
    state_free(cipher_state);
    free(cipher_state);
}

// Fonction de hashage de GCM
void GHASH(state_t **text, state_t *tag, state_t *H, int key_size, long text_length) {
    long number_blocks = text_length / 16;
    int last_block_length = text_length % 16;
    if (last_block_length != 0) {
        number_blocks++;
    }
    for (long i = 0; i < number_blocks; i++) {
        GCM_xor(text[i], tag);
        multiplication_GF128(tag, H);
    }
    state_t *cipher_length = (state_t *)malloc(sizeof(state_t));
    state_allocate(cipher_length, key_size);
    int row = 3;
    int column = 3;
    uint8_t masque = 0xff;
    while (text_length > 255) {
        if (row == 0 && column == 2) {
            errx(EXIT_FAILURE, "The text is too long for the tag, exit.");
        }
        uint8_t value = text_length & masque;
        set_byte(cipher_length, value, row, column);
        row--;
        if (row == -1) {
            row = 3;
            column--;
        }
        text_length >>= 8;
    }
    uint8_t value = text_length & masque;
    set_byte(cipher_length, value, row, column);
    GCM_xor(cipher_length, tag);
    multiplication_GF128(tag, H);
    state_free(cipher_length);
    free(cipher_length);
}

// Renvoie le tag dans un fichier tag.txt
void tag_to_file(state_t *tag) {
    FILE *tag_file = fopen("tag.txt", "w+");
    fprintf(tag_file, "0x");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            char buffer[3];
            uint8_t byte = get_byte(tag, j, i);
            sprintf(buffer, "%x", byte);
            if (byte < 16) {
                buffer[1] = buffer[0];
                buffer[0] = '0';
            }
            fprintf(tag_file, "%s", buffer);
        }
    }
    fclose(tag_file);
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