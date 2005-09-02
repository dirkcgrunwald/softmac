obj-m += softmac_formagemac.o

all: linux_modules
	@echo formage is done

DEPTH=..
include ${PWD}/${DEPTH}/Makefile.inc

clean: linux_clean
	rm -f .*.o.flags *.mod.c *.ko *.o *~ 

install: linux_install
