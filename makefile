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

UTILS_H= src/ut/monocypher.h src/ut/sha512.h src/ut/getopt.h
UTILS_C= src/ut/monocypher.c src/ut/sha512.c src/ut/getopt.c
UTILS_O=    lib/monocypher.o    lib/sha512.o    lib/getopt.o

EXEC_C= src/hash.c
EXEC=   out/hash$(SUFFIX)

.PHONY: all install install-doc \
        check test              \
        clean uninstall         \
        tarball

all: $(EXEC)

clean:
	rm -rf out lib

lib/monocypher.o: src/ut/monocypher.c src/ut/monocypher.h
lib/getopt.o    : src/ut/getopt.c     src/ut/getopt.h
lib/sha512.o    : src/ut/sha512.c     src/ut/sha512.h
$(UTILS_O):
	@mkdir -p lib
	$(CC) -c $(CFLAGS) -I src/ut $< -o $@

out/hash: src/hash.c $(UTILS_O)
$(EXEC):
	@mkdir -p out
	$(CC) $(CFLAGS) -I src/ut $^ -o $@
