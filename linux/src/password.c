/*
 *  password.c
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

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>   // getopt
#include <stdlib.h>   // malloc
#include <locale.h>   // setlocale
#include <iconv.h>    // iconv
#include <langinfo.h> // nl_langinfo
#include <errno.h>    // errno
#include <termios.h>  // tcgetattr,tcsetattr

#include "password.h"
#include "util.h"

/*
 *  read_password_error
 *
 *  Description:
 *      Returns the description of the error when reading the password.
 *
 *  Parameters:
 *      error [in]
 *          An error code indicating the error for which the associated string
 *          should be returned.
 *
 *  Returns:
 *      A pointer to the character string associated with the given error code.
 *
 *  Comments:
 *      None.
 */
const char* read_password_error(int error)
{
    const char *error_string;

    switch(error)
    {
        case AESCRYPT_READPWD_NONE:
            error_string = "password not provided";
            break;

        case AESCRYPT_READPWD_FOPEN:
            error_string = "fopen()";
            break;

        case AESCRYPT_READPWD_FILENO:
            error_string = "fileno()";
            break;

        case AESCRYPT_READPWD_TCGETATTR:
            error_string = "tcgetattr()";
            break;

        case AESCRYPT_READPWD_TCSETATTR:
            error_string = "tcsetattr()";
            break;

        case AESCRYPT_READPWD_FGETC:
            error_string = "fgetc()";
            break;

        case AESCRYPT_READPWD_TOOLONG:
            error_string = "password too long";
            break;

        case AESCRYPT_READPWD_NOMATCH:
            error_string = "passwords don't match";
            break;

        default:
            error_string = "No valid error code specified";
            break;
    }

    return error_string;
}

/*
 *  read_password
 *
 *  Description:
 *      This function reads at most 'MAX_PASSWD_LEN'-1 characters
 *      from the TTY with echo disabled, putting them in 'buffer'.
 *      'buffer' MUST BE ALREADY ALLOCATED!!!
 *      When mode is ENC the function requests password confirmation.
 *
 *  Parameters:
 *      buffer [in]
 *          Buffer into which the password is read.
 *
 *      mode [in]
 *          Indicated whether we are encrypting or decrypting, controlling
 *          whether the password is requested a second time for verification.
 *
 *  Returns:
 *      >= 0 the password length (0 if empty password is in input)
 *      < 0 error (return value indicating the specific error)
 */
int read_password(unsigned char* buffer, encryptmode_t mode)
{
    struct termios t;                   // Used to set ECHO attribute
    int echo_enabled;                   // Was echo enabled?
    int tty;                            // File descriptor for tty
    FILE* ftty;                         // File for tty
    unsigned char pwd_confirm[MAX_PASSWD_BUF];
                                        // Used for password confirmation
    int c;                              // Character read from input
    int chars_read;                     // Chars read from input
    unsigned char* p;                   // Password buffer pointer
    int i;                              // Loop counter
    int match;                          // Do the two passwords match?

    // Open the tty
    ftty = fopen("/dev/tty", "r+");
    if (ftty == NULL)
    {
        return AESCRYPT_READPWD_FOPEN;
    }
    tty = fileno(ftty);
    if (tty < 0)
    {
        return AESCRYPT_READPWD_FILENO;
    }

    // Get the tty attrs
    if (tcgetattr(tty, &t) < 0)
    {
        fclose(ftty);
        return AESCRYPT_READPWD_TCGETATTR;
    }

    // Round 1 - Read the password into buffer
    // (If encoding) Round 2 - read password 2 for confirmation
    for (i = 0; (i == 0) || (i == 1 && mode == ENC); i++)
    {
        // Choose the buffer where to put the password
        if (!i)
        {
            p = buffer;
        }
        else
        {
            p = pwd_confirm;
        }

        // Prompt for password
        if (i)
        {
            fprintf(ftty, "Re-");
        }
        fprintf(ftty, "Enter password: ");
        fflush(ftty);

        // Disable echo if necessary
        if (t.c_lflag & ECHO)
        {
            t.c_lflag &= ~ECHO;
            if (tcsetattr(tty, TCSANOW, &t) < 0)
            {
                // For security reasons, erase the password
                secure_erase(buffer, MAX_PASSWD_BUF);
                secure_erase(pwd_confirm, MAX_PASSWD_BUF);
                fclose(ftty);
                return AESCRYPT_READPWD_TCSETATTR;
            }
            echo_enabled = 1;
        }
        else
        {
            echo_enabled = 0;
        }

        // Read from input and fill buffer till MAX_PASSWD_LEN chars are read
        chars_read = 0;
        while (((c = fgetc(ftty)) != '\n') && (c != EOF))
        {
            // fill buffer till MAX_PASSWD_LEN
            if (chars_read <= MAX_PASSWD_LEN+1)
            {
                if (chars_read <= MAX_PASSWD_LEN)
                    p[chars_read] = (char) c;
                chars_read++;
            }
        }

        if (chars_read <= MAX_PASSWD_LEN)
        {
            p[chars_read] = '\0';
        }

        fprintf(ftty, "\n");

        // Enable echo if disabled above
        if (echo_enabled)
        {
            t.c_lflag |= ECHO;
            if (tcsetattr(tty, TCSANOW, &t) < 0)
            {
                // For security reasons, erase the password
                secure_erase(buffer, MAX_PASSWD_BUF);
                secure_erase(pwd_confirm, MAX_PASSWD_BUF);
                fclose(ftty);
                return AESCRYPT_READPWD_TCSETATTR;
            }
        }

        // check for EOF error
        if (c == EOF)
        {
            // For security reasons, erase the password
            secure_erase(buffer, MAX_PASSWD_BUF);
            secure_erase(pwd_confirm, MAX_PASSWD_BUF);
            fclose(ftty);
            return AESCRYPT_READPWD_FGETC;
        }

        // Check chars_read.  The password must be maximum MAX_PASSWD_LEN
        // chars.  If too long an error is returned
        if (chars_read > MAX_PASSWD_LEN)
        {
            // For security reasons, erase the password
            secure_erase(buffer, MAX_PASSWD_BUF);
            secure_erase(pwd_confirm, MAX_PASSWD_BUF);
            fclose(ftty);
            return AESCRYPT_READPWD_TOOLONG;
        }
    }

    // Close the tty
    fclose(ftty);

    // Password must be compared only when encrypting
    if (mode == ENC)
    {
        // Check if passwords match
        match = strcmp((char*)buffer, (char*)pwd_confirm);
        secure_erase(pwd_confirm, MAX_PASSWD_BUF);

        if (match != 0)
        {
            // For security reasons, erase the password
            secure_erase(buffer, MAX_PASSWD_BUF);
            return AESCRYPT_READPWD_NOMATCH;
        }
    }

    return chars_read;
}

/*
 *  passwd_to_utf16
 *
 *  Description:
 *      Convert String to UTF-16LE for windows compatibility.
 *
 *  Parameters:
 *      in_passwd [in]
 *          The password in the encoding for the current locale.
 *
 *      length [in]
 *          The length of the password in octets.
 *
 *      max_length [in]
 *          The maximum length of the converted password in octets.
 *
 *      out_password [in]
 *          The password converted to UTF-16LE.
 *
 *  Returns:
 *      The length in octets of the converted password.
 *
 *  Comments:
 *      None.
 */
int passwd_to_utf16(unsigned char *in_passwd,
                    int length,
                    int max_length,
                    unsigned char *out_passwd)
{
    unsigned char *ic_outbuf,
                  *ic_inbuf;
    iconv_t condesc;
    size_t ic_inbytesleft,
           ic_outbytesleft;

    // Max length is specified in character, but this function deals
    // with bytes.  So, multiply by two since we are going to create a
    // UTF-16 string.
    max_length *= 2;

    ic_inbuf = in_passwd;
    ic_inbytesleft = length;
    ic_outbytesleft = max_length;
    ic_outbuf = out_passwd;

    // Set the locale based on the current environment
    setlocale(LC_CTYPE,"");

    if ((condesc = iconv_open("UTF-16LE", nl_langinfo(CODESET))) ==
        (iconv_t)(-1))
    {
        perror("Error in iconv_open");
        return -1;
    }

    if (iconv(condesc,
              (char ** const) &ic_inbuf,
              &ic_inbytesleft,
              (char ** const) &ic_outbuf,
              &ic_outbytesleft) == (size_t) -1)
    {
        switch (errno)
        {
            case E2BIG:
                fprintf(stderr, "Error: password too long\n");
                iconv_close(condesc);
                return -1;
                break;
            default:
                /*
                printf("\nEILSEQ(%d), EINVAL(%d), %d\n",
                       EILSEQ,
                       EINVAL,
                       errno);
                */
                perror("Password conversion error");
                iconv_close(condesc);
                return -1;
        }
    }

    iconv_close(condesc);

    return (max_length - ic_outbytesleft);
}
