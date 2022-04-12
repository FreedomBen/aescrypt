/*
 *  aescrypt.h
 *
 *  AES Crypt Command-Line Encryption Tool
 *  Copyright (C) 2022
 *  Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      This is the main module for the command-line version of AES Crypt.
 *
 *  Portability Issues:
 *      None.
 */

#ifndef AESCRYPT_H
#define AESCRYPT_H

#include "aes.h"
#include "sha256.h"

typedef struct {
    char aes[3];
    unsigned char version;
    unsigned char last_block_size;
} aescrypt_hdr;

typedef unsigned char sha256_t[32];

#define AES_CRYPT_MAX_PATH 1024
#define AES_CRYPT_EXTENSION ".aes"
#define AES_CRYPT_EXTENSION_LEN 4

#endif // AESCRYPT_H
