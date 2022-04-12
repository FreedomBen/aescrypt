#
# Makefile for AES Crypt
#
# Copyright (C) 2022
# Paul E. Jones <paulej@packetizer.com>
#
# This Makefile is used to build the command-line version, install the
# output binaries, and the man page.
#

.PHONY: all src

all: src

clean: src

test: src

install: src
	install -o root -g root -m 755 man/aescrypt.1 /usr/share/man/man1/aescrypt.1
	install -o root -g root -m 755 man/aescrypt_keygen.1 /usr/share/man/man1/aescrypt_keygen.1
	gzip /usr/share/man/man1/aescrypt.1
	mandb 2>/dev/null >/dev/null

uninstall: src
	rm -f /usr/share/man/man1/aescrypt.1 /usr/share/man/man1/aescrypt.1.gz
	rm -f /usr/share/man/man1/aescrypt_keygen.1 /usr/share/man/man1/aescrypt_keygen.1.gz
	mandb 2>/dev/null >/dev/null

src:
	$(MAKE) -C $@ $(MAKECMDGOALS)

