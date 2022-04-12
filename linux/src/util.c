/*
 *  util.c
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

#define _POSIX_C_SOURCE 200809L

#include <string.h>

/*
 *  memset_secure
 *
 *  Description:
 *      This function will securely erase memory.  The compiler will not
 *      optimize a call to a volatile function pointer, so this function
 *      should not be compiled out during optimization.
 *
 *  Parameters:
 *      buffer [in]
 *          Pointer to buffer to erase.
 *
 *      length [in]
 *          Number of octets to set to zero.
 *
 *  Returns:
 *      A pointer to the erased buffer.
 *
 *  Comments:
 *      None
 */
void *secure_erase(void *buffer, unsigned length)
{
    // Assign the volatile function pointer to call memset
    static void *(*volatile memset_secure)(void *, int, size_t) = memset;

    return (*memset_secure)(buffer, 0, length);
}
