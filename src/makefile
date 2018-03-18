objs=goldilocks/build/obj/curve25519/decaf.o \
		goldilocks/build/obj/curve25519/decaf_tables.o \
		goldilocks/build/obj/curve25519/scalar.o \
		goldilocks/build/obj/utils.o \
		goldilocks/build/obj/p25519/f_impl.o \
		goldilocks/build/obj/p25519/f_generic.o \
		goldilocks/build/obj/p25519/f_arithmetic.o \
		goldilocks/build/obj/curve25519/elligator.o

PREFIX?=/usr/local
INC=-Igoldilocks/src/GENERATED/include -I/usr/include/sodium
LIBS=-lsodium
CFLAGS=$(INC) -Wall -fPIC -fPIE -O3
LDFLAGS=-g $(LIBS)
CC=gcc
SOEXT=so

all: bin libsphinx.so tests
bin: bin/challenge bin/respond bin/derive bin/2pass

win: CC=x86_64-w64-mingw32-gcc
win: INC=-Igoldilocks/src/GENERATED/include -Iwin/libsodium-win64/include/sodium -Iwin/libsodium-win64/include
win: LIBS=-L. -Lwin/libsodium-win64/lib/ -Wl,-Bstatic -lsodium -Wl,-Bdynamic
win: SOEXT=dll
win: EXT=.exe
win: MAKETARGET=win
win: win/libsodium-win64 exe libsphinx.$(SOEXT) tests$(EXT)
exe: bin/challenge$(EXT) bin/respond$(EXT) bin/derive$(EXT)

tests$(EXT): tests/pake$(EXT) tests/sphinx$(EXT)

$(objs):
	cd goldilocks; OFLAGS='' ARCHFLAGS='' make $(MAKETARGET)

bin/challenge$(EXT): $(objs) bin/challenge.c
	$(CC) $(CFLAGS) -o bin/challenge$(EXT) bin/challenge.c $(LDFLAGS) $(objs)

bin/respond$(EXT): $(objs) bin/respond.c
	$(CC) $(CFLAGS) -o bin/respond$(EXT) bin/respond.c $(LDFLAGS) $(objs)

bin/derive$(EXT): $(objs) bin/derive.c
	$(CC) $(CFLAGS) -o bin/derive$(EXT) bin/derive.c $(LDFLAGS) $(objs)

bin/2pass$(EXT): $(objs) bin/2pass.c
	$(CC) $(CFLAGS) -o bin/2pass$(EXT) bin/2pass.c $(LDFLAGS) $(objs)

libsphinx.$(SOEXT): $(objs) sphinx.o pake.o
	$(CC) -shared -fpic $(CFLAGS) -o libsphinx.$(SOEXT) $(objs) pake.o sphinx.o $(LDFLAGS)

tests/sphinx$(EXT): tests/test.c libsphinx.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/sphinx$(EXT) tests/test.c -L. -lsphinx $(LDFLAGS) $(objs)

tests/pake$(EXT): tests/pake-test.c libsphinx.$(SOEXT)
	$(CC) $(CFLAGS) -o tests/pake$(EXT) tests/pake-test.c -L. -lsphinx $(LDFLAGS) $(objs)

win/libsodium-win64:
	@echo 'win/libsodium-win64 not found.'
	@echo 'download and unpack latest libsodium-*-mingw.tar.gz and unpack into win/'
	@echo 'https://download.libsodium.org/libsodium/releases/'
	@false

install: $(PREFIX)/lib/libsphinx.$(SOEXT) $(PREFIX)/include/sphinx.h

$(PREFIX)/lib/libsphinx.$(SOEXT): libsphinx.$(SOEXT)
	cp $< $@

$(PREFIX)/include/sphinx.h: sphinx.h
	cp $< $@

clean:
	rm -f bin/sphinx bin/challenge bin/respond bin/derive libsphinx.so
	rm -f tests/sphinx tests/pake tests/sphinx.exe tests/pake.exe *.o
	rm -f bin/sphinx.exe bin/challenge.exe bin/respond.exe bin/derive.exe libsphinx.dll

.PHONY: bin clean install
