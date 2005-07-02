obj-m += softmac_core.o

ifndef KERNELSOURCE
KERNELSOURCE=/usr/src/linux
$(warning WARNING: KERNELSOURCE not defined, using ${KERNELSOURCE})
endif

all: softmac_core

softmac_core:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
