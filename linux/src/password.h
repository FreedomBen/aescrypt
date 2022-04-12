/*
 *  password.h
 *
 *  Password Utilities for AES Crypt
 *  Copyright (C) 2022
 *  Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      Password utilities for AES Crypt.
 *
 *  Portability Issues:
 *      None.
 */

#ifndef AESCRYPT_PASSWORD_H
#define AESCRYPT_PASSWORD_H

#define MAX_PASSWD_LEN  1024
#define MAX_PASSWD_BUF  2050 /* MAX_PASSWD_LEN * 2 + 2 -- UTF-16 */

typedef enum {UNINIT, DEC, ENC} encryptmode_t;

// Error codes for read_password function.
#define AESCRYPT_READPWD_NONE         0
#define AESCRYPT_READPWD_FOPEN       -1
#define AESCRYPT_READPWD_FILENO      -2
#define AESCRYPT_READPWD_TCGETATTR   -3
#define AESCRYPT_READPWD_TCSETATTR   -4
#define AESCRYPT_READPWD_FGETC       -5
#define AESCRYPT_READPWD_TOOLONG     -6
#define AESCRYPT_READPWD_NOMATCH     -7

// Function prototypes
const char* read_password_error(int error);
int read_password(unsigned char *buffer, encryptmode_t mode);
int passwd_to_utf16(unsigned char *in_passwd,
                    int length,
                    int max_length,
                    unsigned char *out_passwd);

#endif // AESCRYPT_PASSWORD_H
