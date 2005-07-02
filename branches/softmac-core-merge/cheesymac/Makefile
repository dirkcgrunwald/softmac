obj-m += softmac_cheesymac.o

ifndef KERNELSOURCE
KERNELSOURCE=/usr/src/linux
$(warning WARNING: KERNELSOURCE not defined, using ${KERNELSOURCE})
endif

all:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

install:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} install

clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
