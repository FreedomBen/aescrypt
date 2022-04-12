#
# Makefile for aescrypt
#
# Copyright (C) 2022
# Paul E. Jones <paulej@packetizer.com>
#
# This software is licensed as "freeware."  Permission to distribute
# this software in source and binary forms is hereby granted without a
# fee.  THIS SOFTWARE IS PROVIDED 'AS IS' AND WITHOUT ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
# THE AUTHOR SHALL NOT BE HELD LIABLE FOR ANY DAMAGES RESULTING FROM THE
# USE OF THIS SOFTWARE, EITHER DIRECTLY OR INDIRECTLY, INCLUDING, BUT
# NOT LIMITED TO, LOSS OF DATA OR DATA BEING RENDERED INACCURATE.
#
# AES Crypt binaries are normally built using dynamic linking of libraries.
# To statically link using GCC when building, use this command at the command
# line:
#    $ LDFLAGS=-static make
#

CC=gcc
CFLAGS=-O3 -Wall -Wextra -pedantic -std=c11 -D_FILE_OFFSET_BITS=64
AESCRYPT_OBJS=aescrypt.o aes.o sha256.o password.o keyfile.o util.o
KEYGEN_OBJS=aescrypt_keygen.o keyfile.o password.o util.o

# Linux does not need the iconv library included, though Mac and BSD do
ifeq ($(shell uname -s), Linux)
    LDLIBS=
else
    LDLIBS=-liconv
endif

all: aescrypt aescrypt_keygen

aescrypt: $(AESCRYPT_OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $(AESCRYPT_OBJS) $(LDFLAGS)

aescrypt_keygen: $(KEYGEN_OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $(KEYGEN_OBJS) $(LDFLAGS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $*.c

install: aescrypt
	install -o root -g root -m 755 aescrypt /usr/bin
	install -o root -g root -m 755 aescrypt_keygen /usr/bin

uninstall:
	rm -f /usr/bin/aescrypt
	rm -f /usr/bin/aescrypt_keygen

clean:
	rm -f *.o aescrypt aescrypt_keygen test* *test

test: aescrypt
	@$(CC) -DTEST -o sha.test sha256.c
	@./sha.test
	@rm sha.test
	@$(CC) -DTEST -o aes.test aes.c
	@./aes.test
	@rm aes.test
	# Encrypting and decrypting text files
	# Test zero-length file
	@cat /dev/null > test.orig.txt
	@./aescrypt -e -p "praxis" test.orig.txt
	@cp test.orig.txt.aes test.txt.aes
	@./aescrypt -d -p "praxis" test.txt.aes
	@cmp test.orig.txt test.txt
	@rm test.orig.txt test.orig.txt.aes test.txt.aes test.txt
	# Testing short file (one AES block)
	@echo "Testing..." > test.orig.txt
	@./aescrypt -e -p "praxis" test.orig.txt
	@cp test.orig.txt.aes test.txt.aes
	@./aescrypt -d -p "praxis" test.txt.aes
	@cmp test.orig.txt test.txt
	@rm test.orig.txt test.orig.txt.aes test.txt.aes test.txt
	# Test password length boundary
	# Test password length 0
	@cat /dev/null >test.passwd.txt
	@echo "Testing..." > test.txt
	@# Expecting a failure here, but reflect opposite result code
	@./aescrypt -e -p `cat test.passwd.txt` test.txt 2>/dev/null && \
	    echo Password length test failed && \
	    exit 1 || \
	    true
	@rm test.txt test.passwd.txt
	# Test password length 1023
	@cat /dev/null >test.passwd.txt
	@for x in `seq 1 1023`; do printf X >>test.passwd.txt; done
	@echo "Testing..." > test.txt
	@./aescrypt -e -p `cat test.passwd.txt` test.txt
	@rm test.txt.aes test.txt test.passwd.txt
	# Test password length 1024
	@cat /dev/null >test.passwd.txt
	@for x in `seq 1 1024`; do printf X >>test.passwd.txt; done
	@echo "Testing..." > test.txt
	@./aescrypt -e -p `cat test.passwd.txt` test.txt
	@rm test.txt.aes test.txt test.passwd.txt
	# Test password length 1025
	@cat /dev/null >test.passwd.txt
	@for x in `seq 1 1025`; do printf X >>test.passwd.txt; done
	@echo "Testing..." > test.txt
	@# Expecting a failure here, but reflect opposite result code
	@./aescrypt -e -p `cat test.passwd.txt` test.txt 2>/dev/null && \
	    echo Password length test failed && \
	    exit 1 || \
	    true
	@rm test.txt test.passwd.txt
	# Testing longer file
	@cat /dev/null >test.orig.txt
	@for i in `seq 1 50000`; do echo "This is a test" >>test.orig.txt; done
	@./aescrypt -e -p "praxis" test.orig.txt
	@cp test.orig.txt.aes test.txt.aes
	@./aescrypt -d -p "praxis" test.txt.aes
	@cmp test.orig.txt test.txt
	@rm test.orig.txt test.orig.txt.aes test.txt.aes test.txt
	@echo All file encryption tests passed
