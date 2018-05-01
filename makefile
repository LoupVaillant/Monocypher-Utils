CC=gcc -std=c99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native
DESTDIR=
PREFIX=usr/local
SUFFIX=
MAN_DIR=$(DESTDIR)/$(PREFIX)/share/man/man3

# override with x.y.z when making a proper tarball
TARBALL_VERSION=master
# avoids changing the current directory while we archive it
TARBALL_DIR=..

UTILS_H= src/monocypher.h src/sha512.h src/getopt.h
UTILS_C= src/monocypher.c src/sha512.c src/getopt.c
UTILS_O= lib/monocypher.o lib/sha512.o lib/getopt.o

EXEC_C= src/hash.c
EXEC=   out/hash$(SUFFIX)

.PHONY: all install install-doc \
        check test              \
        clean uninstall         \
        tarball

all: $(EXEC)

clean:
	rm -rf out lib

lib/monocypher.o: src/monocypher.c src/monocypher.h
lib/getopt.o    : src/getopt.c     src/getopt.h
lib/sha512.o    : src/sha512.c     src/sha512.h
$(UTILS_O):
	@mkdir -p lib
	$(CC) -c $(CFLAGS) -I src/ut $< -o $@

out/hash: src/hash.c $(UTILS_O)
$(EXEC):
	@mkdir -p out
	$(CC) $(CFLAGS) -I src/ut $^ -o $@
