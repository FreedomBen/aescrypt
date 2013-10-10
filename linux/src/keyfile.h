/*
 * keyfile.h
 * Copyright (C) 2012, 2013
 * Paul E. Jones <paulej@packetizer.com>
 *
 */

typedef enum {KF_UNK, KF_LE, KF_BE} keyfile_format_t;

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
int ReadKeyFile(char *keyfile, unsigned char *pass);

