obj-m += rs.o softmac_rsmac.o
rs-objs = softmac_rs.o ccsds_tab.o decode_rs.o encode_rs.o

RS=./reed-solomon-4.0

all: rs linux_modules
	mv rs.ko softmac_rs.ko

DEPTH=..
include ${PWD}/${DEPTH}/Makefile.inc

rs: 
	$(MAKE) -C $(RS) ccsds_tab.c
	ln -sf $(RS)/ccsds_tab.c
	ln -sf $(RS)/decode_rs.c
	ln -sf $(RS)/encode_rs.c
	ln -sf $(RS)/fixed.h
	ln -sf $(RS)/rs.h

rs.o: ${rs-objs}
	$(LD) $(LDOPTS) -o rs.o -r $(rs-objs)

clean: linux_clean
	rm -f .*.o.flags *.mod.c *.ko *.o *~ ccsds_tab.c decode_rs.c encode_rs.c fixed.h rs.h
	$(MAKE) -C $(RS) clean

install: linux_install
