#include "AES.h"

#include <time.h>

struct Params parameters = {
    .key_size = 16, .round = 10, .key = NULL, .cipher_mod = true, .encoding_mod = ECB, .initialized_mod = false};

int main(int argc, char **argv) {
    int c = 0;
    int option_index = 0;
    static struct option long_options[] = {{"key", required_argument, NULL, 'k'},
                                           {"decipher", no_argument, NULL, 'd'},
                                           {"help", no_argument, NULL, 'h'},
                                           {"CBC", required_argument, NULL, 'c'},
                                           {"CFB", required_argument, NULL, 'f'},
                                           {"OFB", required_argument, NULL, 'o'},
                                           {"GCM", required_argument, NULL, 'g'},
                                           {"WBC", no_argument, NULL, 'w'},
                                           {0, 0, 0, 0}};

    while ((c = getopt_long(argc, argv, "k:dhc:f:o:g:w", long_options, &option_index)) != -1) {
        switch (c) {
            // Change la clé utilisée
            case 'k':
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
                if (parameters.key_size == 24) parameters.round = 12;
                if (parameters.key_size == 32) parameters.round = 14;
                parameters.expanded_key = (uint8_t *)malloc(16 * (parameters.round + 1) * sizeof(uint8_t));
                expansionKey(parameters.key, parameters.expanded_key, parameters.round);
                break;

            // Passe en mode déchiffrement
            case 'd':
                parameters.cipher_mod = false;
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
                memcpy(parameters.IV, IV, 12);
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
                    "Usage: \t\tAES [-k FILE] TEXT_FILE\n"
                    "\t\tAES -d [-k FILE] TEXT_FILE\n"
                    "Cipher or decipher the TEXT_FILE using AES.\n"
                    "-k FILE, --key FILE \t\tuse the key in the file\n"
                    "-d, --decipher \t\t\tswitch to decipher mode\n"
                    "-h, --help \t\t\tdisplay this help and exit\n"
                    "The encoding mode is ECB by default, these options change the encoding mode :\n"
                    "-c IV_FILE, --CBC IV_FILE \tswitch the encoding mode to CBC.\n"
                    "-f IV_FILE, --CFB IV_FILE \tswitch the encoding mode to CFB.\n"
                    "-o IV_FILE, --OFB IV_FILE \tswitch the encoding mode to OFB.\n"
                    "-g IV_FILE, --GCM IV_FILE \tswitch the encoding mode to GCM.\n"
                    "-w, --WBC \t\t\tuse the White-Box ciphering. (Only available with 128-bit key, ECB mode)\n");
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
        long blocks_number = (length / 16) + 1;
        bool padding = (length % 16) == 0;

        FILE *output_file = fopen("cipher.txt", "w+");
        if (output_file == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            fclose(file);
            errx(EXIT_FAILURE, "Couldn't create cipher.txt, exit.");
        }

        uint8_t block[16];
        char texte[16];

        if (parameters.encoding_mod == ECB) {
            for (long i = 0; i < blocks_number-1; i++) {
                fread(block, 1, 16, file);
                cipher(block, parameters.expanded_key, parameters.round);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
            }
            if (padding) {
                memset(block, 16, 16);
            } else {
                size_t read_bytes = fread(block, 1, 16, file);
                for (size_t j = read_bytes; j < 16; j++) {
                    block[j] = 16 - read_bytes;
                }
            }
            cipher(block, parameters.expanded_key, parameters.round);
            memcpy(texte, block, 16);
            fwrite(texte, 1, 16, output_file);
        }

        else if (parameters.encoding_mod == CBC) {
            uint8_t old_block[16];
            memcpy(old_block, parameters.IV, 16);
            for (long i = 0; i < blocks_number - 1; i++) {
                fread(block, 1, 16, file);
                for (int k = 0; k < 16; k++) {
                    block[k] ^= old_block[k];
                }
                cipher(block, parameters.expanded_key, parameters.round);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
                memcpy(old_block, block, 16);
            }
            if (padding) {
                memset(block, 16, 16);
            } else {
                size_t read_bytes = fread(block, 1, 16, file);
                for (size_t j = read_bytes; j < 16; j++) {
                    block[j] = 16 - read_bytes;
                }
            }
            for (int k = 0; k < 16; k++) {
                block[k] ^= old_block[k];
            }
            cipher(block, parameters.expanded_key, parameters.round);
            memcpy(texte, block, 16);
            fwrite(texte, 1, 16, output_file);
        }

        else if (parameters.encoding_mod == CFB) {
            if (padding) blocks_number--;
            uint8_t cipher_IV[16];
            memcpy(cipher_IV, parameters.IV, 16);
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(cipher_IV, parameters.expanded_key, parameters.round);
                fread(block, 1, 16, file);
                CFB_xor(cipher_IV, block, 16);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
                CFB_shift(cipher_IV, block, 16);
            }
            cipher(cipher_IV, parameters.expanded_key, parameters.round);
            size_t read_bytes = fread(block, 1, 16, file);
            CFB_xor(cipher_IV, block, read_bytes);
            memcpy(texte, block, read_bytes);
            fwrite(texte, 1, read_bytes, output_file);
        }

        else if (parameters.encoding_mod == OFB) {
            if (padding) blocks_number--;
            uint8_t cipher_IV[16];
            memcpy(cipher_IV, parameters.IV, 16);
            for (long i = 0; i < blocks_number; i++) {
                cipher(cipher_IV, parameters.expanded_key, parameters.round);
                size_t read_bytes = fread(block, 1, 16, file);
                CFB_xor(cipher_IV, block, read_bytes);
                memcpy(texte, block, read_bytes);
                fwrite(texte, 1, read_bytes, output_file);
            }
        }

        else if (parameters.encoding_mod == GCM) {
            uint8_t IV_inc[16];
            memcpy(IV_inc, parameters.IV, 16);
            increment(IV_inc, 15);

            uint8_t H[16] = {0};
            cipher(H, parameters.expanded_key, parameters.round);

            uint8_t tag[16] = {0};

            if (padding) {
                blocks_number--;
            }
            uint8_t cipher_counter[16];

            for (long i = 0; i < blocks_number; i++) {
                size_t read_bytes = fread(block, 1, 16, file);
                memcpy(cipher_counter, IV_inc, 16);
                cipher(cipher_counter, parameters.expanded_key, parameters.round);
                for (size_t k = 0; k < read_bytes; k++) {
                    block[k] ^= cipher_counter[k];
                }
                increment(IV_inc, 15);
                for (size_t k = 0; k < read_bytes; k++) {
                    tag[k] ^= block[k];
                }
                multiplication_GF128(tag, H);
                memcpy(texte, block, 16);
                fwrite(texte, 1, read_bytes, output_file);
            }

            uint8_t cipher_length[16] = {0};
            uint64_t total_bits = (uint64_t)length * 8;
            for (int i = 7; i >= 0; i--) {
                uint8_t val = (uint8_t)(total_bits & 0xff);
                cipher_length[(8 + i)] = val;
                total_bits >>= 8;
            }
            for (int k = 0; k < 16; k++) {
                tag[k] ^= cipher_length[k];
            }
            multiplication_GF128(tag, H);

            uint8_t cipher_IV[16];
            memcpy(cipher_IV, parameters.IV, 16);
            cipher(cipher_IV, parameters.expanded_key, parameters.round);

            for (int k = 0; k < 16; k++) {
                tag[k] ^= cipher_IV[k];
            }
            fwrite(tag, 1, 16, output_file);
        }

        else if (parameters.encoding_mod == WBC) {
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
            WBC_cipher_v2(file, blocks_number, mixInput, mixOutput, Xor);
        }

        free(parameters.key);
        free(parameters.expanded_key);
        fclose(file);
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
        long blocks_number = (length / 16);
        if (length % 16 != 0) blocks_number++;

        FILE *output_file = fopen("decipher.txt", "w+");
        if (output_file == NULL) {
            free(parameters.key);
            free(parameters.expanded_key);
            fclose(file);
            errx(EXIT_FAILURE, "Couldn't create cipher.txt, exit.");
        }

        uint8_t block[16];
        char texte[16];

        if (parameters.encoding_mod == ECB) {
            for (long i = 0; i < blocks_number - 1; i++) {
                fread(block, 1, 16, file);
                decipher(block, parameters.expanded_key, parameters.round);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
            }
            fread(block, 1, 16, file);
            decipher(block, parameters.expanded_key, parameters.round);
            int padding = block[15];
            if (padding < 1 || padding > 16) {
                free(parameters.key);
                free(parameters.expanded_key);
                fclose(file);
                fclose(output_file);
                errx(EXIT_FAILURE, "The padding is not correct, exit.");
            }
            for (int i = 16 - padding; i < 16; i++) {
                if (block[i] != padding) {
                    free(parameters.key);
                    free(parameters.expanded_key);
                    fclose(file);
                    fclose(output_file);
                    errx(EXIT_FAILURE, "The padding is not correct, exit.");
                }
            }
            memcpy(texte, block, 16 - padding);
            fwrite(texte, 1, 16 - padding, output_file);
        }

        else if (parameters.encoding_mod == CBC) {
            uint8_t old_block[16];
            uint8_t old_cipher[16];
            memcpy(old_block, parameters.IV, 16);
            for (long i = 0; i < blocks_number - 1; i++) {
                fread(block, 1, 16, file);
                memcpy(old_cipher, block, 16);
                decipher(block, parameters.expanded_key, parameters.round);
                for (int k = 0; k < 16; k++) {
                    block[k] ^= old_block[k];
                }
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
                memcpy(old_block, old_cipher, 16);
            }
            fread(block, 1, 16, file);
            decipher(block, parameters.expanded_key, parameters.round);
            for (int k = 0; k < 16; k++) {
                block[k] ^= old_block[k];
            }
            int padding = block[15];
            if (padding < 1 || padding > 16) {
                free(parameters.key);
                free(parameters.expanded_key);
                fclose(file);
                fclose(output_file);
                errx(EXIT_FAILURE, "The padding is not correct, exit.");
            }
            for (int i = 16 - padding; i < 16; i++) {
                if (block[i] != padding) {
                    free(parameters.key);
                    free(parameters.expanded_key);
                    fclose(file);
                    fclose(output_file);
                    errx(EXIT_FAILURE, "The padding is not correct, exit.");
                }
            }
            memcpy(texte, block, 16 - padding);
            fwrite(texte, 1, 16 - padding, output_file);
        }

        else if (parameters.encoding_mod == CFB) {
            uint8_t decipher_IV[16];
            memcpy(decipher_IV, parameters.IV, 16);
            uint8_t temp[16];
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(decipher_IV, parameters.expanded_key, parameters.round);
                fread(block, 1, 16, file);
                memcpy(temp, block, 16);
                CFB_xor(decipher_IV, block, 16);
                CFB_shift(decipher_IV, temp, 16);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
            }
            cipher(decipher_IV, parameters.expanded_key, parameters.round);
            size_t read_bytes = fread(block, 1, 16, file);
            CFB_xor(decipher_IV, block, read_bytes);
            memcpy(texte, block, read_bytes);
            fwrite(texte, 1, read_bytes, output_file);
        }

        else if (parameters.encoding_mod == OFB) {
            uint8_t decipher_IV[16];
            memcpy(decipher_IV, parameters.IV, 16);
            for (long i = 0; i < blocks_number - 1; i++) {
                cipher(decipher_IV, parameters.expanded_key, parameters.round);
                fread(block, 1, 16, file);
                CFB_xor(decipher_IV, block, 16);
                memcpy(texte, block, 16);
                fwrite(texte, 1, 16, output_file);
            }
            cipher(decipher_IV, parameters.expanded_key, parameters.round);
            size_t read_bytes = fread(block, 1, 16, file);
            CFB_xor(decipher_IV, block, read_bytes);
            memcpy(texte, block, read_bytes);
            fwrite(texte, 1, read_bytes, output_file);
        }

        else if (parameters.encoding_mod == GCM) {
            if (length < 16) {
                free(parameters.key);
                free(parameters.expanded_key);
                fclose(file);
                fclose(output_file);
                errx(EXIT_FAILURE, "Ciphertext file is too short to contain a tag, exit.");
            }

            long ciphertext_length = length - 16;
            long ciphertext_blocks = ciphertext_length / 16;
            if (ciphertext_length % 16 != 0) {
                ciphertext_blocks++;
            }

            // Lecture du tag de 16 octets à la fin du fichier
            uint8_t expected_tag[16];
            fseek(file, ciphertext_length, SEEK_SET);
            if (fread(expected_tag, 1, 16, file) != 16) {
                free(parameters.key);
                free(parameters.expanded_key);
                fclose(file);
                fclose(output_file);
                errx(EXIT_FAILURE, "Couldn't read tag from ciphertext file, exit.");
            }
            fseek(file, 0, SEEK_SET);

            uint8_t H[16] = {0};
            cipher(H, parameters.expanded_key, parameters.round);

            uint8_t tag[16] = {0};

            for (long i = 0; i < ciphertext_blocks; i++) {
                size_t to_read = 16;
                if ((long)(i * 16 + 16) > ciphertext_length) {
                    to_read = ciphertext_length - i * 16;
                }
                size_t read_bytes = fread(block, 1, to_read, file);
                for (size_t k = 0; k < read_bytes; k++) {
                    tag[k] ^= block[k];
                }
                multiplication_GF128(tag, H);
            }

            uint8_t cipher_length[16] = {0};
            uint64_t total_bits = (uint64_t)ciphertext_length * 8;
            for (int i = 7; i >= 0; i--) {
                uint8_t val = (uint8_t)(total_bits & 0xff);
                cipher_length[(8 + i)] = val;
                total_bits >>= 8;
            }
            for (int k = 0; k < 16; k++) {
                tag[k] ^= cipher_length[k];
            }
            multiplication_GF128(tag, H);

            uint8_t cipher_IV[16];
            memcpy(cipher_IV, parameters.IV, 16);
            cipher(cipher_IV, parameters.expanded_key, parameters.round);

            for (int k = 0; k < 16; k++) {
                tag[k] ^= cipher_IV[k];
            }

            if (memcmp(tag, expected_tag, 16) != 0) {
                free(parameters.key);
                free(parameters.expanded_key);
                fclose(file);
                fclose(output_file);
                errx(EXIT_FAILURE, "The tag is not correct, exit.");
            }

            fseek(file, 0, SEEK_SET);
            uint8_t IV_inc[16];
            memcpy(IV_inc, parameters.IV, 16);
            increment(IV_inc, 15);

            uint8_t cipher_counter[16];

            for (long i = 0; i < ciphertext_blocks; i++) {
                size_t to_read = 16;
                if ((long)(i * 16 + 16) > ciphertext_length) {
                    to_read = ciphertext_length - i * 16;
                }
                size_t read_bytes = fread(block, 1, to_read, file);
                memcpy(cipher_counter, IV_inc, 16);
                cipher(cipher_counter, parameters.expanded_key, parameters.round);
                for (size_t k = 0; k < read_bytes; k++) {
                    block[k] ^= cipher_counter[k];
                }
                increment(IV_inc, 15);
                fwrite(block, 1, read_bytes, output_file);
            }
        }

        free(parameters.key);
        free(parameters.expanded_key);
        fclose(file);
        fclose(output_file);
        exit(EXIT_SUCCESS);
    }
}