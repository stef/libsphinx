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

all: sphinx challenge respond derive

sphinx: $(objs) sphinx.c
	gcc $(CFLAGS) -o sphinx sphinx.c $(LDFLAGS) $(objs)

challenge: $(objs) challenge.c
	gcc $(CFLAGS) -o challenge challenge.c $(LDFLAGS) $(objs)

respond: $(objs) respond.c
	gcc $(CFLAGS) -o respond respond.c $(LDFLAGS) $(objs)

derive: $(objs) derive.c
	gcc $(CFLAGS) -o derive derive.c $(LDFLAGS) $(objs)

clean:
	@rm sphinx challenge respond derive
