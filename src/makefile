objs=goldilocks/build/obj/curve25519/decaf.o \
		goldilocks/build/obj/curve25519/decaf_tables.o \
		goldilocks/build/obj/curve25519/scalar.o \
		goldilocks/build/obj/utils.o \
		goldilocks/build/obj/p25519/f_impl.o \
		goldilocks/build/obj/p25519/f_generic.o \
		goldilocks/build/obj/p25519/f_arithmetic.o \
		goldilocks/build/obj/curve25519/elligator.o

INC=-Igoldilocks/src/GENERATED/include -I/usr/include/sodium
LIBS=-lsodium
CFLAGS=$(INC) -Wall -Os
LDFLAGS=-g $(LIBS)

all: bin libsphinx.so tests

bin: bin/challenge bin/respond bin/derive

tests: tests/pake tests/sphinx

$(objs):
	cd goldilocks; make

bin/challenge: $(objs) bin/challenge.c
	gcc $(CFLAGS) -o bin/challenge bin/challenge.c $(LDFLAGS) $(objs)

bin/respond: $(objs) bin/respond.c
	gcc $(CFLAGS) -o bin/respond bin/respond.c $(LDFLAGS) $(objs)

bin/derive: $(objs) bin/derive.c
	gcc $(CFLAGS) -o bin/derive bin/derive.c $(LDFLAGS) $(objs)

libsphinx.so: $(objs) sphinx.o pake.o
	$(CC) -shared -fpic $(CFLAGS) -o $@ $(objs) pake.o sphinx.o $(LDFLAGS)

tests/sphinx: tests/test.c libsphinx.so
	gcc $(CFLAGS) -o tests/sphinx tests/test.c -lsphinx $(LDFLAGS) $(objs)

tests/pake: tests/pake-test.c libsphinx.so
	gcc $(CFLAGS) -o tests/pake tests/pake-test.c -lsphinx $(LDFLAGS) $(objs)

clean:
	@rm -f bin/sphinx bin/challenge bin/respond bin/derive libsphinx.so *.o *.pyc || true
	@rm -f tests/sphinx tests/pake || true
	@rm -rf __pycache__ || true

.PHONY: bin clean
