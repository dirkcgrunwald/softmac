obj-m += softmac_netif.o
#obj-m += startstop.o
#startstop-objs := start.o stop.o

KERNELSOURCE=/usr/src/linux

install:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules
	
clean:
	@rm -f *.ko *.mod.c .*o.cmd