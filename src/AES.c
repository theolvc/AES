#include "AES.h"

#include <time.h>

struct Params parameters = {
    .key_size = 16, .key = NULL, .cipher_mod = true, .encoding_mod = ECB, .initialized_mod = false, .block_length = 16};

int main(int argc, char **argv) {
    int c = 0;
    int option_index = 0;
    static struct option long_options[] = {{"key", required_argument, NULL, 'k'},
                                           {"decipher", optional_argument, NULL, 'd'},
                                           {"help", no_argument, NULL, 'h'},
                                           {"CBC", required_argument, NULL, 'c'},
                                           {"CFB", required_argument, NULL, 'f'},
                                           {"OFB", required_argument, NULL, 'o'},
                                           {"GCM", required_argument, NULL, 'g'},
                                           {"WBC", no_argument, NULL, 'w'},
                                           {0, 0, 0, 0}};

    while ((c = getopt_long(argc, argv, "k:d::hc:f:o:g:w", long_options, &option_index)) != -1) {
        switch (c) {
            // Change la clé utilisée
            case 'k':
                parameters.key_size = 16;
                char *arg = argv[optind - 1];
                if (arg == NULL) {
                    errx(EXIT_FAILURE, "No key given, exit.");
                }
                FILE *key_file = fopen(arg, "r");
                if (key_file == NULL) {
                    errx(EXIT_FAILURE, "Key file not found, exit.");
                }
                parameters.key_size = key_length(key_file);
                parameters.key = (uint8_t *)malloc(parameters.key_size * sizeof(uint8_t));
                key_parser(parameters.key, key_file);
                fclose(key_file);
                int round = 10;
                if (parameters.key_size == 24) round = 12;
                if (parameters.key_size == 32) round = 14;
                parameters.expanded_key = (uint8_t *)malloc(16 * (round + 1) * sizeof(uint8_t));
                expansionKey(parameters.key, parameters.expanded_key, round);
                break;

            // Passe en mode déchiffrement
            case 'd':
                parameters.cipher_mod = false;
                if (optarg != NULL) {
                    arg = optarg;
                    FILE *tag_file = fopen(arg, "r");
                    if (tag_file == NULL) {
                        errx(EXIT_FAILURE, "Tag file not found, exit.");
                    }
                    IV_parser(parameters.tag, tag_file);
                    fclose(tag_file);
                }
                break;

            // Change le mode de chiffrement en CBC
            case 'c':
                if (parameters.initialized_mod) {
                    errx(EXIT_FAILURE, "Can't use two encoding mode, exit.");
                }
                parameters.encoding_mod = CBC;
                parameters.initialized_mod = true;
                arg = argv[optind - 1];
                if (arg == NULL) {
                    errx(EXIT_FAILURE, "No IV given, exit.");
                }
                FILE *IV_file = fopen(arg, "r");
                if (IV_file == NULL) {
                    errx(EXIT_FAILURE, "IV file not found, exit.");
                }
                IV_parser(parameters.IV, IV_file);
                fclose(IV_file);
                break;

            // Change le mode de chiffrement en CFB
            case 'f':
                if (parameters.initialized_mod) {
                    errx(EXIT_FAILURE, "Can't use two encoding mode, exit.");
                }
                parameters.encoding_mod = CFB;
                parameters.initialized_mod = true;
                arg = argv[optind - 1];
                if (arg == NULL) {
                    errx(EXIT_FAILURE, "No IV given, exit.");
                }
                IV_file = fopen(arg, "r");
                if (IV_file == NULL) {
                    errx(EXIT_FAILURE, "IV file not found, exit.");
                }
                IV_parser(parameters.IV, IV_file);
                fclose(IV_file);
                break;

            // Change le mode de chiffrement en OFB
            case 'o':
                if (parameters.initialized_mod) {
                    errx(EXIT_FAILURE, "Can't use two encoding mode, exit.");
                }
                parameters.encoding_mod = OFB;
                parameters.initialized_mod = true;
                arg = argv[optind - 1];
                if (arg == NULL) {
                    errx(EXIT_FAILURE, "No IV given, exit.");
                }
                IV_file = fopen(arg, "r");
                if (IV_file == NULL) {
                    errx(EXIT_FAILURE, "IV file not found, exit.");
                }
                IV_parser(parameters.IV, IV_file);
                fclose(IV_file);
                break;

            // Change le mode de chiffrement en GCM
            case 'g':
                if (parameters.initialized_mod) {
                    errx(EXIT_FAILURE, "Can't use two encoding mode, exit.");
                }
                parameters.encoding_mod = GCM;
                parameters.initialized_mod = true;
                arg = argv[optind - 1];
                if (arg == NULL) {
                    errx(EXIT_FAILURE, "No IV given, exit.");
                }
                IV_file = fopen(arg, "r");
                if (IV_file == NULL) {
                    errx(EXIT_FAILURE, "IV file not found, exit.");
                }
                uint8_t IV[12];
                IV_GCM_parser(IV, IV_file);
                for (int i = 0; i < 12; i++) {
                    parameters.IV[i] = IV[i];
                }
                parameters.IV[15] = 1;
                fclose(IV_file);
                break;

            case 'w':
                if (parameters.initialized_mod) {
                    errx(EXIT_FAILURE, "Can't use encoding mode with WBC, exit.");
                }
                parameters.encoding_mod = WBC;
                parameters.initialized_mod = true;
                break;

            // Affiche une aide
            case 'h':
                printf(
                    "Usage: \t\tAES -w [-k FILE] TEXT_FILE\n"
                    "\t\tAES -d [-k FILE] TEXT_FILE\n"
                    "Cipher or decipher the TEXT_FILE using AES.\n"
                    "-w, -WBC \t\t\tuse the White-Box ciphering.\n"
                    "-k FILE, --key FILE \t\tuse the key in the file (Please use a 128-bit key)\n"
                    "-d, --decipher \t\t\tswitch to decipher mode\n"
                    "-h, --help \t\t\tdisplay this help and exit\n"
                    "Others options are not relevant for the White-Box AES.\n");
                exit(EXIT_SUCCESS);

            default:
                errx(EXIT_FAILURE,
                     "Option not recognised, you can see the help with the "
                     "option -h or --help");
        }
    };

    // Créer la clé par défault si aucune clé n'a été utilisé
    if (parameters.key == NULL) {
        uint8_t *key = (uint8_t *)malloc(16 * sizeof(uint8_t));
        for (int i = 0; i < 16; i++) {
            key[i] = i;
        }
        parameters.key = key;
        parameters.expanded_key = (uint8_t *)malloc(176 * sizeof(uint8_t));
        expansionKey(parameters.key, parameters.expanded_key, 10);
    }

    // Chiffrement
    if (parameters.cipher_mod) {
        char *input = argv[optind];
        if (input == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "No text given to cipher, exit.");
        }
        if (argv[optind + 1] != NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "Too much argument given, exit.");
        }

        FILE *file = fopen(input, "r");
        if (file == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "Couldn't open the file, exit.");
        }
        long length = text_length(file);
        if (parameters.encoding_mod == CFB || parameters.encoding_mod == OFB) {
            parameters.block_length = find_block_size(length);
        }
        long blocks_number = length / parameters.block_length;
        // Rajout d'un bloc en plus si padding
        if (length % parameters.block_length != 0) blocks_number++;
        state_t **blocks = (state_t **)malloc(blocks_number * sizeof(state_t *));
        file_parser(blocks, file, parameters.key_size, length, parameters.block_length);
        fclose(file);

        if (parameters.encoding_mod == ECB) {
            for (long i = 0; i < blocks_number; i++) {
                cipher(blocks[i], parameters.expanded_key);
            }
        }

        if (parameters.encoding_mod == CBC) {
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    set_byte(blocks[0], get_byte(blocks[0], j, i) ^ parameters.IV[4 * i + j], j, i);
                }
            }
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(blocks[i], parameters.expanded_key);
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        set_byte(blocks[i + 1], get_byte(blocks[i + 1], k, j) ^ get_byte(blocks[i], k, j), k, j);
                    }
                }
            }
            cipher(blocks[blocks_number - 1], parameters.expanded_key);
        }

        if (parameters.encoding_mod == CFB) {
            state_t *cipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(cipher_IV, parameters.key_size);
            IV_to_state(cipher_IV, parameters.IV);
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(cipher_IV, parameters.expanded_key);
                CFB_xor(cipher_IV, blocks[i], parameters.block_length);
                CFB_shift(cipher_IV, blocks[i], parameters.block_length);
            }
            cipher(cipher_IV, parameters.expanded_key);
            CFB_xor(cipher_IV, blocks[blocks_number - 1], parameters.block_length);
            state_free(cipher_IV);
            free(cipher_IV);
        }

        if (parameters.encoding_mod == OFB) {
            state_t *cipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(cipher_IV, parameters.key_size);
            IV_to_state(cipher_IV, parameters.IV);
            for (long i = 0; i < blocks_number; i++) {
                cipher(cipher_IV, parameters.expanded_key);
                CFB_xor(cipher_IV, blocks[i], parameters.block_length);
            }
            state_free(cipher_IV);
            free(cipher_IV);
        }

        if (parameters.encoding_mod == GCM) {
            uint8_t *IV_inc = (uint8_t *)malloc(16 * sizeof(uint8_t));
            for (int i = 0; i < 16; i++) {
                IV_inc[i] = parameters.IV[i];
            }
            increment(IV_inc, 15);
            GCTR(blocks, IV_inc, parameters.expanded_key, parameters.key_size, length);
            free(IV_inc);
            state_t *H = (state_t *)malloc(sizeof(state_t));
            state_allocate(H, parameters.key_size);
            cipher(H, parameters.expanded_key);
            state_t *tag = (state_t *)malloc(sizeof(state_t));
            state_allocate(tag, parameters.key_size);
            GHASH(blocks, tag, H, parameters.key_size, length);
            state_free(H);
            free(H);
            state_t *cipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(cipher_IV, parameters.key_size);
            IV_to_state(cipher_IV, parameters.IV);
            cipher(cipher_IV, parameters.expanded_key);
            GCM_xor(cipher_IV, tag);
            tag_to_file(tag);
            state_free(cipher_IV);
            free(cipher_IV);
            state_free(tag);
            free(tag);
        }

        if (parameters.encoding_mod == WBC) {
            if (parameters.key_size != 16) {
                errx(EXIT_FAILURE, "The White-Box implementation is only available with 128-bit key, exit.");
            }
            uint8_t Xor[9][96][16][16];
            XOR_table(Xor);
            uint32_t TBoxesTyiTables[9][16][256];
            uint8_t lastTbox[16][256];
            composing_tables(TBoxesTyiTables, lastTbox, parameters.key);
            uint32_t mixInput[10][16][256];
            uint32_t mixOutput[9][16][256];
            mixBijections(mixInput, mixOutput, TBoxesTyiTables, lastTbox);
            WBC_cipher_v2(blocks, blocks_number, mixInput, mixOutput, Xor);
        }

        // Écrit le chiffré dans le texte cipher.txt
        char *texte = (char *)malloc(parameters.block_length * blocks_number * sizeof(char));
        state_to_char(blocks, texte, blocks_number, parameters.block_length);
        FILE *output_file = fopen("cipher.txt", "w+");
        // Enlève le padding en mode GCM
        if (parameters.encoding_mod == GCM) {
            int space = (parameters.block_length - (length % parameters.block_length)) % parameters.block_length;
            for (long i = 0; i < parameters.block_length * blocks_number - space; i++) {
                fprintf(output_file, "%c", texte[i]);
            }
        } else {
            for (long i = 0; i < parameters.block_length * blocks_number; i++) {
                fprintf(output_file, "%c", texte[i]);
            }
        }

        for (long i = 0; i < blocks_number; i++) {
            state_free(blocks[i]);
            free(blocks[i]);
        }
        free(blocks);
        free(parameters.key);
        free(parameters.expanded_key);
        free(texte);
        fclose(output_file);
        exit(EXIT_SUCCESS);
    }

    // Déchiffrement
    else {
        char *input = argv[optind];
        if (input == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "No text given to decipher, exit.");
        }
        if (argv[optind + 1] != NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "Too much argument given, exit.");
        }

        FILE *file = fopen(input, "r");
        if (file == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            errx(EXIT_FAILURE, "Couldn't open the file, exit.");
        }
        long length = text_length(file);
        if (parameters.encoding_mod == CFB || parameters.encoding_mod == OFB) {
            parameters.block_length = find_block_size(length);
        }
        long blocks_number = length / parameters.block_length;
        if (length % parameters.block_length != 0) blocks_number++;
        state_t **blocks = (state_t **)malloc(blocks_number * sizeof(state_t *));
        file_parser(blocks, file, parameters.key_size, length, parameters.block_length);
        fclose(file);

        if (parameters.encoding_mod == ECB) {
            for (long i = 0; i < blocks_number; i++) {
                decipher(blocks[i], parameters.expanded_key);
            }
        }

        if (parameters.encoding_mod == CBC) {
            for (long i = blocks_number - 1; i > 0; i--) {
                decipher(blocks[i], parameters.expanded_key);
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        set_byte(blocks[i], get_byte(blocks[i], k, j) ^ get_byte(blocks[i - 1], k, j), k, j);
                    }
                }
            }
            decipher(blocks[0], parameters.expanded_key);
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    set_byte(blocks[0], get_byte(blocks[0], j, i) ^ parameters.IV[4 * i + j], j, i);
                }
            }
        }

        if (parameters.encoding_mod == CFB) {
            state_t *decipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(decipher_IV, parameters.key_size);
            IV_to_state(decipher_IV, parameters.IV);
            state_t *temp = (state_t *)malloc(sizeof(state_t));
            state_allocate(temp, parameters.key_size);
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(decipher_IV, parameters.expanded_key);
                copy_state(blocks[i], temp);
                CFB_xor(decipher_IV, blocks[i], parameters.block_length);
                CFB_shift(decipher_IV, temp, parameters.block_length);
            }
            cipher(decipher_IV, parameters.expanded_key);
            CFB_xor(decipher_IV, blocks[blocks_number - 1], parameters.block_length);
            state_free(decipher_IV);
            free(decipher_IV);
            state_free(temp);
            free(temp);
        }

        if (parameters.encoding_mod == OFB) {
            state_t *decipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(decipher_IV, parameters.key_size);
            IV_to_state(decipher_IV, parameters.IV);
            for (long i = 0; i < blocks_number; i++) {
                cipher(decipher_IV, parameters.expanded_key);
                CFB_xor(decipher_IV, blocks[i], parameters.block_length);
            }
            state_free(decipher_IV);
            free(decipher_IV);
        }

        if (parameters.encoding_mod == GCM) {
            state_t *H = (state_t *)malloc(sizeof(state_t));
            state_allocate(H, parameters.key_size);
            cipher(H, parameters.expanded_key);
            state_t *tag = (state_t *)malloc(sizeof(state_t));
            state_allocate(tag, parameters.key_size);
            GHASH(blocks, tag, H, parameters.key_size, length);
            state_free(H);
            free(H);
            state_t *cipher_IV = (state_t *)malloc(sizeof(state_t));
            state_allocate(cipher_IV, parameters.key_size);
            IV_to_state(cipher_IV, parameters.IV);
            cipher(cipher_IV, parameters.expanded_key);
            GCM_xor(cipher_IV, tag);
            state_free(cipher_IV);
            free(cipher_IV);
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    if (get_byte(tag, j, i) != parameters.tag[4 * i + j]) {
                        state_free(tag);
                        free(tag);
                        free(parameters.key);
                        free(parameters.expanded_key);
                        errx(EXIT_FAILURE, "The tag is not correct, exit.");
                    }
                }
            }
            state_free(tag);
            free(tag);
            uint8_t *IV_inc = (uint8_t *)malloc(16 * sizeof(uint8_t));
            for (int i = 0; i < 16; i++) {
                IV_inc[i] = parameters.IV[i];
            }
            increment(IV_inc, 15);
            GCTR(blocks, IV_inc, parameters.expanded_key, parameters.key_size, length);
            free(IV_inc);
        }

        char *texte = (char *)malloc(parameters.block_length * blocks_number * sizeof(char));
        state_to_char(blocks, texte, blocks_number, parameters.block_length);
        FILE *output_file = fopen("decipher.txt", "w+");
        if (parameters.encoding_mod == GCM) {
            int space = (parameters.block_length - (length % parameters.block_length)) % parameters.block_length;
            for (long i = 0; i < parameters.block_length * blocks_number - space; i++) {
                fprintf(output_file, "%c", texte[i]);
            }
        } else {
            for (long i = 0; i < parameters.block_length * blocks_number; i++) {
                fprintf(output_file, "%c", texte[i]);
            }
        }

        for (long i = 0; i < blocks_number; i++) {
            state_free(blocks[i]);
            free(blocks[i]);
        }
        free(blocks);
        free(parameters.key);
        free(parameters.expanded_key);
        free(texte);
        fclose(output_file);
        exit(EXIT_SUCCESS);
    }
}