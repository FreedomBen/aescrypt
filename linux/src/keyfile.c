/*
 * keyfile.c
 * Copyright (C) 2012, 2013
 * Paul E. Jones <paulej@packetizer.com>
 *
 * Read the encryption key from a key file
 */

#include <stdio.h>
#include "password.h"
#include "keyfile.h"

/*
 * ReadKeyFile
 *
 * This function will read the password from the specified key file.
 *
 * Parameters:
 *     keyfile [in] - The pathname of the file to read
 *     pass [out] - A pre-allocated buffer to hold the password
 *
 * Returns:
 *     The length of the password or a negative value if there was an error.
 */
int ReadKeyFile(char *keyfile, unsigned char *pass)
{
    FILE *fp = NULL;
    int bytes_read;
    char temp;
    int endian = KF_UNK;
    unsigned char buffer[2];
    int passlen = 0;
    int pass_max_len = MAX_PASSWD_LEN * 2;

    // Try to open the key file
    if ((fp = fopen(keyfile, "r")) == NULL)
    {
        perror("Error: unable to read the specified key file");
        return -1;
    }

    // Read the Byte Order Mark (BOM)
    if ((bytes_read = fread(buffer, 1, 2, fp)) != 2)
    {
        fprintf(stderr, "Error: unable to read the BOM\n");
        fclose(fp);
        return -1;
    }

    // Determine if the BOM is present and its value
    if (((buffer[0] == 0xFF) && (buffer[1] == 0xFE)) ||
        ((buffer[0] == 0xFE) && (buffer[1] == 0xFF)))
    {
        if (buffer[0] == 0xFF)
        {
            endian = KF_LE;
        }
        else
        {
            endian = KF_BE;
        }
    }
    else
    {
        fprintf(stderr, "Error: key file does not have a valid BOM\n");
        fclose(fp);
        return -1;
    }

    // Read two bytes at a time, ensuring the password is composed
    // in UTF-16LE order in memory
    while ((bytes_read = fread(buffer, 1, 2, fp)) > 0)
    {
        if (bytes_read != 2)
        {
            fprintf(stderr, "Error: Keyfile has an odd number of octets\n");
            fclose(fp);
            return -1;
        }

        /* Put the octets in little endian order if necessary */
        if (endian == KF_BE)
        {
            temp = buffer[0];
            buffer[0] = buffer[1];
            buffer[1] = temp;
        }

        /* Let's stop if we see a NL or CR character */
        if ((buffer[1] == 0x00) &&
            ((buffer[0] == 0x0D) || (buffer[0] == 0x0A)))
        {
            break;
        }

        /* Assign these octets of the password */
        passlen += 2;
        if (passlen > pass_max_len)
        {
            fprintf(stderr, "Error: password in keyfile is too long\n");
            fclose(fp);
            return -1;
        }
        *pass++ = buffer[0];
        *pass++ = buffer[1];
    }

    fclose(fp);

    return passlen;
}

