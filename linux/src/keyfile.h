/*
 *  keyfile.h
 *
 *  Key File Utilities for AES Crypt
 *  Copyright (C) 2022
 *  Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      Key File Utilities for AES Crypt.
 *
 *  Portability Issues:
 *      None.
 */

typedef enum {KF_UNK, KF_LE, KF_BE} keyfile_format_t;

/*
 *  ReadKeyFile
 *
 *  Description:
 *      This function will read the password from the specified key file.
 *
 *  Parameters:
 *      keyfile [in]
 *          The pathname of the file to read
 *
 *      pass [out]
 *          A pre-allocated buffer to hold the password
 *
 *  Returns:
 *      The length of the password or a negative value if there was an error.
 *
 *  Comments:
 *      None.
 */
int ReadKeyFile(char *keyfile, unsigned char *pass);
