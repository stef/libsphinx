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

all: standalone libsphinx.so tests

standalone: standalone/challenge standalone/respond standalone/derive

tests: tests/pake tests/sphinx

$(objs):
	cd goldilocks; make

standalone/challenge: $(objs) standalone/challenge.c
	gcc $(CFLAGS) -o standalone/challenge standalone/challenge.c $(LDFLAGS) $(objs)

standalone/respond: $(objs) standalone/respond.c
	gcc $(CFLAGS) -o standalone/respond standalone/respond.c $(LDFLAGS) $(objs)

standalone/derive: $(objs) standalone/derive.c
	gcc $(CFLAGS) -o standalone/derive standalone/derive.c $(LDFLAGS) $(objs)

libsphinx.so: $(objs) sphinx.o pake.o
	$(CC) -shared -fpic $(CFLAGS) -o $@ $(objs) pake.o sphinx.o $(LDFLAGS)

tests/sphinx: test.c libsphinx.so
	gcc $(CFLAGS) -o tests/sphinx test.c -lsphinx $(LDFLAGS) $(objs)

tests/pake: pake-test.c libsphinx.so
	gcc $(CFLAGS) -o tests/pake pake-test.c -lsphinx $(LDFLAGS) $(objs)

clean:
	@rm -f standalone/sphinx standalone/challenge standalone/respond standalone/derive libsphinx.so *.o *.pyc || true
	@rm -f tests/sphinx tests/pake || true
	@rm -rf __pycache__ || true

.PHONY: standalone clean
