/*****************************************************************************

Encrypts/decrypts file in dm-crypt compatible way, using kernel crypto API.
Copyright (c) 2013 Maxim Radugin.

Usage: dmcryptfile <arguments>

This utility is designed to encrypt disk/partition image files in userspace
without root priviledges and without using device mapper and cryptsetup.
Currently supports only plain mode, no LUKS support!
Backend code is taken from cryptsetup.
Input key size should be of desired cipher key size.
Key is passed directly to the cipher algorithm, no hashing or any other
processing is performed. It is up to the user to provide strong key.
For available ciphers, chain modes and key sizes check /proc/crypto.
Only plain IV mode is supported.
Input file size must be multiple of sector size i.e. 512 bytes.
If input file is not multiple of sector size, output will be truncated.

******************************************************************************

The MIT License (MIT)

Copyright (c) 2013 Maxim Radugin.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*****************************************************************************/

#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <string.h>
#include <getopt.h>    /* for getopt_long; standard getopt is in unistd.h */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "crypto_backend.h"

#define SECTOR_SIZE 512

#define FILENAME_LEN 255

enum {
    ACTION_NONE,
    ACTION_ENCRYPT,
    ACTION_DECRYPT
};

static struct option long_options[] =
{
    {"cipher",    required_argument, 0, 'c'},
    {"key-size",    required_argument, 0, 's'},
    {"key-file",    required_argument, 0, 'k'},
    {"in-file",    required_argument, 0, 'i'},
    {"out-file",    required_argument, 0, 'o'},
    {"enc", no_argument, 0, 'e'},
    {"dec", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {0, 0, 0, 0}
};

void display_usage(char* name) {
    printf("Encrypts/decrypts file in dm-crypt compatible way, using kernel crypto API.\n");
    printf("Copyright (c) 2013 Maxim Radugin.\n\n");

    printf("Usage: %s <arguments>\n\n", name);

    printf("This utility is designed to encrypt disk/partition image files in userspace\n");
    printf("without root priviledges and without using device mapper and cryptsetup.\n");
    printf("Currently supports only plain mode, no LUKS support!\n");
    printf("Backend code is taken from cryptsetup.\n");
    printf("Input key size should be of desired cipher key size.\n");
    printf("Key is passed directly to the cipher algorithm, no hashing or any other\n");
    printf("processing is performed. It is up to the user to provide strong key.\n");
    printf("For available ciphers, chain modes and key sizes check /proc/crypto.\n");
    printf("Only plain IV mode is supported.\n");
    printf("Input file size must be multiple of sector size i.e. %d bytes.\n", SECTOR_SIZE);
    printf("If input file is not multiple of sector size, output will be truncated.\n\n");
    printf("Mandatory arguments:\n");
    printf(" --cipher,-c   Cipher-chainmode-ivmode, for example, aes-xts-plain\n");
    printf(" --key-size,-s Size of key in bytes\n");
    printf(" --key-file,-k Input key file, should be at least key-size bytes.\n");
    printf("               Key data after key-size is ignored.\n");
    printf(" --in-file,-i  Input file\n");
    printf(" --out-file,-o Output file\n");
    printf(" --enc,-e      Perform encryption operation from input to output file.\n");
    printf(" --dec,-d      Perform decryption operation from input to output file.\n");
    printf(" --help,-h,-?  Display this text.\n");

}

int main(int argc, char * const argv[]) {
    int option_index = 0;
    int c;

    int action = ACTION_NONE;
    char infile[FILENAME_LEN] = {0};
    char outfile[FILENAME_LEN] = {0};

    int in_fd = -1;
    int out_fd = -1;

    char keyfile[FILENAME_LEN] = {0};
    char *key = 0;
    int keysize = 0;

    int error = 0;

    char ciphername[21] = {0};
    char chainmode[21] = {0};
    char ivmode[21] = {0};

    struct crypt_cipher* cipher = 0;

    while ((c = getopt_long (argc, argv, "eds:f:c:i:o:h?",
            long_options, &option_index)) != -1) {
        switch (c) {
            case 0:
                break;
            case 'e':
                action = ACTION_ENCRYPT;
                break;
            case 'd':
                action = ACTION_DECRYPT;
                break;
            case 'i':
                if (optarg) {
                    snprintf((char*)&infile, FILENAME_LEN, "%s", optarg);
                }
                break;
            case 'o':
                if (optarg) {
                    snprintf((char*)&outfile, FILENAME_LEN, "%s", optarg);
                }
                break;
            case 'k':
                if (optarg) {
                    snprintf((char*)&keyfile, FILENAME_LEN, "%s", optarg);
                }
                break;
            case 's':
                if (optarg)
                    sscanf(optarg, "%i", &keysize);
                break;
            case 'c':
                if (optarg) {
                    if (sscanf(optarg, "%20[^-]-%20[^-]-%20s", (char*)&ciphername, (char*)&chainmode, (char*)&ivmode) != 3) {
                        fprintf(stderr, "Invalid cipher format specified %s, expected format cipher-chainmode-ivmode\n", optarg);
                        error = 1;
                    }
                    else {
                        printf("Cipher: %s, chain mode: %s, iv mode: %s\n", ciphername, chainmode, ivmode);
                        if (strcmp(ivmode, "plain") != 0) {
                            fprintf(stderr, "Only plain iv mode is supported, sorry\n");
                            error = 1;
                        }
                    }
                }
                break;
            case '?':
            case 'h':
                display_usage(argv[0]);
                return 0;
                break;
            default:
                break;
        }
    }

    if (!strlen((const char *)&keyfile) || !strlen((const char *)&infile) || !strlen((const char *)&outfile)) {
        error = 1;
    }

    if (!error) {
        int key_fd = open((const char*)&keyfile, O_RDONLY);
        if (key_fd < 0) {
            perror("Unable to open key file");
        }
        else {
            key = (char*)malloc(keysize);
            if (read(key_fd, key, keysize) != keysize) {
                fprintf(stderr, "Key file size should be at least %d bytes\n", keysize);
                error = 1;
                free(key);
                key = 0;
            }
            else {
                printf("Key loaded from %s, %d bits\n", (char*)&keyfile, keysize*8);
            }
        }
    }

    if (!error) {
        in_fd = open((const char*)&infile, O_RDONLY);
        if (in_fd < 0) {
            perror("Unable to open input file");
            error = 1;
        }
        out_fd = open((const char*)&outfile, O_CREAT | O_TRUNC| O_RDWR);
        if (out_fd < 0) {
            perror("Unable to create output file");
            error = 1;
        }
    }

    if (!error) {
        int r = crypt_cipher_init(&cipher, (char*)&ciphername, (char*)&chainmode, key, keysize);
        if (r != 0) {
            fprintf(stderr, "Failed to init cipher, check /proc/crypto for available ciphers and chain modes\n");
            error = 1;
        }
    }

    if (!error) {
        char sector[SECTOR_SIZE];
        char out_sector[SECTOR_SIZE];
        char iv[16];
        int r = 0;
        unsigned int scnt = 0;
        memset((void*)&iv, 0, sizeof(iv));
        printf("Processing...\n");
        while ((r = read(in_fd, (char*)&sector, SECTOR_SIZE)) == SECTOR_SIZE) {
            *(unsigned int *)iv = scnt & 0xffffffff;
            if (action == ACTION_ENCRYPT) {
                if (crypt_cipher_encrypt(cipher, (char*)&sector, (char*)&out_sector, SECTOR_SIZE, (char*)&iv, sizeof(iv)) == 0) {
                    if (write(out_fd, (char*)&out_sector, SECTOR_SIZE) != SECTOR_SIZE) {
                        perror("Write error");
                        error = 2;
                        break;
                    }
                }
                else {
                    fprintf(stderr, "Encryption error\n");
                    error = 3;
                    break;
                }
            }
            if (action == ACTION_DECRYPT) {
                if (crypt_cipher_decrypt(cipher, (char*)&sector, (char*)&out_sector, SECTOR_SIZE, (char*)&iv, sizeof(iv)) == 0) {
                    if (write(out_fd, (char*)&out_sector, SECTOR_SIZE) != SECTOR_SIZE) {
                        perror("Write error");
                        error = 2;
                        break;
                    }
                }
                else {
                    fprintf(stderr, "Decryption error\n");
                    error = 3;
                    break;
                }
            }
            scnt++;
        }
        if ((r > 0) && (r != SECTOR_SIZE)) {
            fprintf(stderr, "Invalid input file size, should be multiple of %d bytes, output file truncated!\n", SECTOR_SIZE);
        }

        if (!error) {
            printf("Done.\n");
            if (action == ACTION_ENCRYPT) {
               printf("To use produced image with cryptosetup, under super user issue:\n");
               printf("cryptsetup open %s <name> --type plain --cipher %s-%s-%s --key-size=%d --key-file=%s\n", outfile, ciphername, chainmode, ivmode, keysize*8, keyfile);
            }
        }
    }
    else {
        fprintf(stderr, "Invalid arguments specified, see --help\n");
    }

    if (in_fd >= 0)
        close(in_fd);

    if (out_fd >= 0)
        close(out_fd);

    if (cipher) {
        crypt_cipher_destroy(cipher);
    }

    if (key) {
        free(key);
    }

    return error;
}



