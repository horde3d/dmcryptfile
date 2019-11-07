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
#define _LARGEFILE64_SOURCE

#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <string.h>
#include <getopt.h>    /* for getopt_long; standard getopt is in unistd.h */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

#include "crypto_backend.h"

static const size_t SECTOR_SIZE = 512;

#define CIPHER_NAME_MAX 21

enum {
    ACTION_NONE,
    ACTION_ENCRYPT,
    ACTION_DECRYPT
};

static struct option long_options[] =
{
    {"cipher",      required_argument, 0, 'c'},
    {"key-size",    required_argument, 0, 's'},
    {"key-file",    required_argument, 0, 'f'},
    {"in-file",     required_argument, 0, 'i'},
    {"out-file",    required_argument, 0, 'o'},
    {"enc",         no_argument,       0, 'e'},
    {"dec",         no_argument,       0, 'd'},
    {"help",        no_argument,       0, 'h'},
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
    printf("Input file size must be multiple of sector size i.e. %lu bytes.\n", SECTOR_SIZE);
    printf("If input file is not multiple of sector size, output will be truncated.\n\n");
    printf("Mandatory arguments:\n");
    printf(" --cipher,-c   Cipher-chainmode-ivmode, for example, aes-xts-plain\n");
    printf(" --key-size,-s Size of key in bytes\n");
    printf(" --key-file,-f Input key file, should be at least key-size bytes.\n");
    printf("               Key data after key-size is ignored.\n");
    printf(" --in-file,-i  Input file\n");
    printf(" --out-file,-o Output file\n");
    printf(" --enc,-e      Perform encryption operation from input to output file.\n");
    printf(" --dec,-d      Perform decryption operation from input to output file.\n");
    printf(" --help,-h,-?  Display this text.\n");

}

char* load_key(const char* keyfile, int keysize)
{
    char* key = NULL;
    int key_fd = open(keyfile, O_RDONLY);
    if (key_fd < 0) {
        perror("Unable to open key file");
    }
    else {
        key = (char*)malloc(keysize);
        if (read(key_fd, key, keysize) != keysize) {
            fprintf(stderr, "Key file size should be at exactly %d bytes\n", keysize);
            free(key);
            key = NULL;
        }
        else {
            printf("Key loaded from %s, %d bits\n", (char*)&keyfile, keysize*8);
        }
        close(key_fd);
    }
    return key;
}

int main(int argc, char * const argv[]) {
    int action = ACTION_NONE;
    char infile[PATH_MAX] = {0};
    char outfile[PATH_MAX] = {0};

    int in_fd = -1;
    int out_fd = -1;

    char keyfile[PATH_MAX] = {0};
    char *key = NULL;
    int keysize = 0;

    int error = 0;

    char ciphername[CIPHER_NAME_MAX] = {0};
    char chainmode[CIPHER_NAME_MAX] = {0};
    char ivmode[CIPHER_NAME_MAX] = {0};

    struct crypt_cipher* cipher = NULL;

    int option_index = 0;
    int c;
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
                    snprintf(infile, PATH_MAX, "%s", optarg);
                }
                break;
            case 'o':
                if (optarg) {
                    snprintf(outfile, PATH_MAX, "%s", optarg);
                }
                break;
            case 'f':
                if (optarg) {
                    snprintf(keyfile, PATH_MAX, "%s", optarg);
                }
                break;
            case 's':
                if (optarg) {
                    sscanf(optarg, "%i", &keysize);
                }
                break;
            case 'c':
                if (optarg) {
                    if (sscanf(optarg, "%20[^-]-%20[^-]-%20s", ciphername, chainmode, ivmode) != 3) {
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

    if (action == ACTION_NONE)
    {
        fprintf(stderr, "Action - encrypt/decrypt not specified\n");
        return 1;
    }

    if (!strlen(keyfile))
    {
        fprintf(stderr, "Key file not specified\n");
        return 1;
    }
    if (!strlen(infile))
    {
        fprintf(stderr, "Input file not specified\n");
        return 1;
    }
    if (!strlen(outfile))
    {
        fprintf(stderr, "Output file not specified\n");
        return 1;
    }

    key = load_key(keyfile, keysize);
    if (!key)
    {
        return 1;
    }

    if (strcmp((const char*)&infile, (const char*)&outfile) != 0) {
        in_fd = open((const char*)&infile, O_RDONLY);
        if (in_fd < 0) {
            perror("Unable to open input file");
            error = 1;
        }
        out_fd = open((const char*)&outfile, O_CREAT | O_TRUNC | O_RDWR, (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP));
        if (out_fd < 0) {
            perror("Unable to create output file");
            error = 1;
        }
    }
    else {
        in_fd = open((const char*)&infile, O_RDWR);
        if (in_fd < 0) {
            perror("Unable to open input file");
            error = 1;
        }
        out_fd = in_fd;
    }

    if (!error) {
        int r = crypt_cipher_init(&cipher, (char*)&ciphername, (char*)&chainmode, key, keysize);
        if (r != 0) {
            fprintf(stderr, "Failed to init cipher, check /proc/crypto for available ciphers and chain modes\n");
            error = 1;
        }
    }

    if (!error) {
        const size_t BUFFER_SECTOR_COUNT = 2048;
        const size_t BUFFER_SIZE = SECTOR_SIZE * BUFFER_SECTOR_COUNT;
        char read_buffer[BUFFER_SIZE];
        char write_buffer[BUFFER_SIZE];
        char iv[16] = {};
        int bytes_read = 0;
        size_t scnt = 0;
        printf("Processing...\n");
        while (!error && (bytes_read = read(in_fd, read_buffer, BUFFER_SIZE)) > 0) {
            if (bytes_read % SECTOR_SIZE != 0)
            {
                perror("Read size is not multiple of sector size");
                error = 5;
                break;
            }
            // Same file for output
            if (in_fd == out_fd) {
                off64_t pos = lseek64(in_fd, 0, SEEK_CUR);
                if (pos != (off64_t)(-1)) {
                    pos = lseek64(in_fd, pos - bytes_read, SEEK_SET);
                    if (pos == (off64_t)(-1)) {
                        perror("Seek error");
                        error = 4;
                        break;
                    }
                }
                else {
                    perror("Seek error");
                    error = 4;
                    break;
                }
            }

            for (size_t offset = 0; offset < (size_t)bytes_read; offset += SECTOR_SIZE)
            {
                *(unsigned int *)iv = scnt & 0xffffffff;

                if (action == ACTION_ENCRYPT) {
                    if (crypt_cipher_encrypt(cipher, read_buffer + offset,
                                             write_buffer + offset, SECTOR_SIZE,
                                             iv, sizeof(iv)) != 0) {
                        fprintf(stderr, "Encryption error\n");
                        error = 3;
                        break;
                    }
                }
                if (action == ACTION_DECRYPT) {
                    if (crypt_cipher_decrypt(cipher, read_buffer + offset,
                                             write_buffer + offset, SECTOR_SIZE,
                                             iv, sizeof(iv)) != 0) {
                        fprintf(stderr, "Decryption error\n");
                        error = 3;
                        break;
                    }
                }
                scnt++;
                offset += SECTOR_SIZE;
            }
            if (write(out_fd, write_buffer, bytes_read) != bytes_read) {
                perror("Write error");
                error = 2;
                break;
            }
        }

        if (!error) {
            printf("Done.\n");
            if (action == ACTION_ENCRYPT) {
               printf("To use produced image with cryptsetup, under super user issue:\n");
               printf("cryptsetup open %s <name> --type plain --cipher %s-%s-%s --key-size=%d --key-file=%s\n", outfile, ciphername, chainmode, ivmode, keysize*8, keyfile);
            }
        }
    }
    else {
        fprintf(stderr, "Invalid arguments specified, see --help\n");
    }

    if (in_fd != out_fd) {
        if (in_fd >= 0) {
            close(in_fd);
        }

        if (out_fd >= 0) {
            close(out_fd);
        }
    }
    else {
        if (in_fd >= 0) {
            close(in_fd);
        }
    }

    if (cipher) {
        crypt_cipher_destroy(cipher);
    }

    if (key) {
        free(key);
    }

    return error;
}
