/*
 *  util.h
 *
 *  Utility Functions for AES Crypt
 *  Copyright (C) 2022
 *  Paul E. Jones <paulej@packetizer.com>
 *
 *  Description:
 *      Module to provide miscellanous utility functions for AES Crypt.
 *
 *  Portability Issues:
 *      None.
 */

#ifndef AESCRYPT_UTIL_H
#define AESCRYPT_UTIL_H

// Securely erase memory
void *secure_erase(void *buffer, unsigned length);

#endif // AESCRYPT_UTIL_H
