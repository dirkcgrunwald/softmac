# Copyright 2002 Phil Karn, KA9Q
# May be used under the terms of the GNU General Public License (GPL)
# Generated automatically from makefile.in by configure.
srcdir = .
prefix = /usr/local
exec_prefix=${prefix}
CC=gcc

CFLAGS=-g -O2 -march=i686 -Wall

LIB=	encode_rs_char.o encode_rs_int.o encode_rs_8.o \
	decode_rs_char.o decode_rs_int.o decode_rs_8.o \
	init_rs_char.o init_rs_int.o ccsds_tab.o \
	encode_rs_ccsds.o decode_rs_ccsds.o ccsds_tal.o

all: librs.a librs.so.4.0.0

test: rstest
	./rstest

rstest: rstest.o exercise_int.o exercise_char.o exercise_8.o exercise_ccsds.o \
	librs.a
	gcc -g -o $@ $^

install: all
	mkdir -p ${exec_prefix}/lib 
	install -D -m 644 -p librs.a librs.so.4.0.0 ${exec_prefix}/lib
	(cd ${exec_prefix}/lib;ln -f -s librs.so.4.0.0 librs.so)
	ldconfig
	mkdir -p ${prefix}/include
	install -m 644 -p rs.h ${prefix}/include
	mkdir -p ${prefix}/man/man3
	install -m 644 rs.3 ${prefix}/man/man3

librs.a: $(LIB)
	ar rv $@ $^

librs.so.4.0.0: librs.a
	gcc -shared -Xlinker -soname=librs.so.4 -o $@ -Wl,-whole-archive $^ -Wl,-no-whole-archive -lc

encode_rs_char.o: encode_rs.c
	gcc $(CFLAGS) -c -o $@ $^

encode_rs_int.o: encode_rs.c
	gcc -DBIGSYM=1 $(CFLAGS) -c -o $@ $^

encode_rs_8.o: encode_rs.c
	gcc -DFIXED=1 $(CFLAGS) -c -o $@ $^

decode_rs_char.o: decode_rs.c
	gcc $(CFLAGS) -c -o $@ $^

decode_rs_int.o: decode_rs.c
	gcc -DBIGSYM=1 $(CFLAGS) -c -o $@ $^

decode_rs_8.o: decode_rs.c
	gcc -DFIXED=1 $(CFLAGS) -c -o $@ $^

init_rs_char.o: init_rs.c
	gcc $(CFLAGS) -c -o $@ $^

init_rs_int.o: init_rs.c
	gcc -DBIGSYM=1 $(CFLAGS) -c -o $@ $^

ccsds_tab.o: ccsds_tab.c

ccsds_tab.c: gen_ccsds
	./gen_ccsds > ccsds_tab.c

gen_ccsds: gen_ccsds.o init_rs_char.o
	gcc -o $@ $^

gen_ccsds.o: gen_ccsds.c
	gcc  $(CFLAGS) -c -o $@ $^

ccsds_tal.o: ccsds_tal.c

ccsds_tal.c: gen_ccsds_tal
	./gen_ccsds_tal > ccsds_tal.c

exercise_char.o: exercise.c
	gcc $(CFLAGS) -c -o $@ $^

exercise_int.o: exercise.c
	gcc -DBIGSYM=1 $(CFLAGS) -c -o $@ $^

exercise_8.o: exercise.c
	gcc -DFIXED=1 $(CFLAGS) -c -o $@ $^

exercise_ccsds.o: exercise.c
	gcc -DCCSDS=1 $(CFLAGS) -c -o $@ $^


clean:
	rm -f *.o *.a ccsds_tab.c ccsds_tal.c gen_ccsds gen_ccsds_tal \
	rstest librs.so.4.0.0

distclean: clean
	rm -f config.log config.cache config.status config.h makefile


