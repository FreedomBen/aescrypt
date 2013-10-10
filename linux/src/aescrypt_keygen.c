/*
 *  AES Crypt Key File Generator
 *  Copyright (C) 2007, 2008, 2009, 2013
 *  Paul E. Jones <paulej@packetizer.com>
 *
 * This software is licensed as "freeware."  Permission to distribute
 * this software in source and binary forms is hereby granted without a
 * fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM
 * THE USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING,
 * BUT NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
 *
 * --------------------------------------------------------------------------
 *
 * This program will accept a password as input and then generate a file
 * to store the user's password in UTF-16 format.  This file can then be
 * referenced by AES Crypt via the -k flag so that passwords are not
 * manually-entered or appears on the command-line (and visible via the
 * ps utility on Linux systems).
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // getopt
#include <iconv.h> // iconv stuff
#include <langinfo.h> // nl_langinfo
#include <errno.h> // errno

#include "password.h"
#include "version.h"

/*
 * generate_password
 *
 * This function will generate a password by reading random octets
 * from /dev/urandom.  The length of the password may be specified
 * as the first argument.  The function returns the length of
 * the password once converted to UTF-16LE.
 *
 * The logic for this function was borrowed from pwgen.  We utilize
 * only 62 characters, but what is more important is the password length.
 * More details can be found at http://www.packetizer.com/security/pwgen/.
 * You will find a complete explanation of the strength of various
 * password lengths.
 */
int generate_password(int length, unsigned char *password)
{
    const char pwchars[] =
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
        's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F',
        'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z'
    };

    FILE *randfp;
    unsigned char pwtemp[MAX_PASSWD_BUF];
    unsigned char *p;
    int i, n;
    int passlen;
    
    if ((length <= 0) || (length > MAX_PASSWD_LEN))
    {
        fprintf(stderr, "Invalid password length specified.\n");
        return -1;
    }

    /* Open the device to read random octets */
    if ((randfp = fopen("/dev/urandom", "r")) == NULL)
    {
        perror("Error open /dev/urandom:");
        return  -1;
    }

    /* Read random octets */
    if ((n = fread((char*)pwtemp, 1, length, randfp)) != length)
    {
        fprintf(stderr, "Error: Couldn't read from /dev/urandom\n");
        fclose(randfp);
        return  -1;
    }
    fclose(randfp);

    /* Now ensure each octet is uses the defined character set */
    for(i = 0, p = pwtemp; i < length; i++, p++)
    {
        *p = pwchars[((int)(*p)) % 62];
    }

    /* Convert the password to UTF-16LE */
    passlen = passwd_to_utf16(  pwtemp,
                                length,
                                MAX_PASSWD_LEN,
                                password);

    return passlen;
}

/*
 *  usage
 *
 *  Displays the program usage to the user.
 */
void usage(const char *progname)
{
    const char* progname_real; //contains the real name of the program (without path)

    progname_real = rindex(progname, '/');
    if (progname_real == NULL) //no path in progname: use progname
    {
        progname_real = progname;
    }
    else
    {
        progname_real++;
    }

    fprintf(stderr, "\nusage: %s [ { -g <password length>] | [-p <password> } ] <keyfile>\n\n", progname_real);
}

/*
 *  version
 *
 *  Displays the program version to the user.
 */
void version(const char *progname)
{
    const char* progname_real; //contains the real name of the program (without path)

    progname_real = rindex(progname, '/');
    if (progname_real == NULL) //no path in progname: use progname
    {
        progname_real = progname;
    }
    else
    {
        progname_real++;
    }

    fprintf(stderr, "\n%s version %s (%s)\n\n",
            progname_real, PROG_VERSION, PROG_DATE);
}

/*
 *  cleanup
 *
 *  Removes output files that are not fully and properly created.
 */
void cleanup(const char *outfile)
{
    if (strcmp(outfile,"-") && outfile[0] != '\0')
    {
        unlink(outfile);
    }
}

int main(int argc, char *argv[])
{
    int rc=0, passlen=0;
    FILE *outfp = NULL;
    char outfile[1024];
    unsigned char pass_input[MAX_PASSWD_BUF],
                  pass[MAX_PASSWD_BUF];
    int file_count = 0;
    unsigned char bom[2];
    int password_acquired = 0;

    while ((rc = getopt(argc, argv, "vhg:p:o:")) != -1)
    {
        switch (rc)
        {
            case 'h':
                usage(argv[0]);
                return 0;
            case 'v':
                version(argv[0]);
                return 0;
            case 'g':
                if (password_acquired)
                {
                    fprintf(stderr, "Error: password supplied twice\n");
                    return -1;
                }
                if (optarg != 0)
                {
                    passlen = generate_password(atoi((char*) optarg),
                                                pass);
                    if (passlen < 0)
                    {
                        return -1;
                    }
                }
                password_acquired = 1;
                break;
            case 'p':
                if (password_acquired)
                {
                    fprintf(stderr, "Error: password supplied twice\n");
                    return -1;
                }
                if (optarg != 0)
                {
                    passlen = passwd_to_utf16(  (unsigned char*) optarg,
                                                strlen((char *)optarg),
                                                MAX_PASSWD_LEN,
                                                pass);
                    if (passlen < 0)
                    {
                        return -1;
                    }
                }
                password_acquired = 1;
                break;
            default:
                fprintf(stderr, "Error: Unknown option '%c'\n", rc);
        }
    }
    
    file_count = argc - optind;
    if (file_count != 1)
    {
        fprintf(stderr, "Error: A single output file must be specified.\n");
        usage(argv[0]);
        // For security reasons, erase the password
        memset(pass, 0, MAX_PASSWD_BUF);
        return -1;
    }
    else
    {
        /* What is the filename for the key file? */
        strncpy(outfile, argv[optind++], 1024);
        outfile[1023] = '\0';
    }

    // Prompt for password if not provided on the command line
    if (passlen == 0)
    {
        passlen = read_password(pass_input, ENC);

        switch (passlen)
        {
            case 0: //no password in input
                fprintf(stderr, "Error: No password supplied.\n");
                return -1;
            case AESCRYPT_READPWD_FOPEN:
            case AESCRYPT_READPWD_FILENO:
            case AESCRYPT_READPWD_TCGETATTR:
            case AESCRYPT_READPWD_TCSETATTR:
            case AESCRYPT_READPWD_FGETC:
            case AESCRYPT_READPWD_TOOLONG:
                fprintf(stderr, "Error in read_password: %s.\n",
                        read_password_error(passlen));
                return -1;
            case AESCRYPT_READPWD_NOMATCH:
                fprintf(stderr, "Error: Passwords don't match.\n");
                return -1;
        }

        passlen = passwd_to_utf16(  pass_input,
                                    strlen((char*) pass_input),
                                    MAX_PASSWD_LEN,
                                    pass);

        if (passlen < 0)
        {
            // For security reasons, erase the password
            memset(pass, 0, MAX_PASSWD_BUF);
            return -1;
        }
    }

    if(!strcmp("-", outfile))
    {
        outfp = stdout;
    }
    else if ((outfp = fopen(outfile, "w")) == NULL)
    {
        fprintf(stderr, "Error opening output file %s : ", outfile);
        perror("");
        // For security reasons, erase the password
        memset(pass, 0, MAX_PASSWD_BUF);
        return  -1;
    }

    /* Write the BOM.  AES Crypt uses UTF-16LE */
    bom[0] = 0xFF;
    bom[1] = 0xFE;
    if (fwrite(bom, 1, 2, outfp) != 2)
    {
        fprintf(stderr, "Error: Could not write BOM to password file.\n");
        if (strcmp("-",outfile))
        {
            fclose(outfp);
        }
        cleanup(outfile);
        return  -1;
    }
    
    if (fwrite(pass, 1, passlen, outfp) != passlen)
    {
        fprintf(stderr, "Error: Could not write password file.\n");
        if (strcmp("-",outfile))
        {
            fclose(outfp);
        }
        cleanup(outfile);
        return  -1;
    }

    /* Close the output file, so long as it is not stdout */
    if (strcmp("-",outfile))
    {
        fclose(outfp);
    }

    // For security reasons, erase the password
    memset(pass, 0, MAX_PASSWD_BUF);

    return rc;
}
