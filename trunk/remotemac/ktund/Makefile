obj-m += ktund.o
ktund-objs = main.o proc.o
DEPTH = ../..

all: linux_modules tap

include ${PWD}/${DEPTH}/Makefile.inc

tap: tap.c
	gcc -g -O2 -o tap tap.c

ktund.o: ${ktund-objs}

clean: linux_clean
	rm -f tap

install: linux_install