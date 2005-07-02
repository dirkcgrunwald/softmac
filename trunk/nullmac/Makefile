obj-m += softmac_nullmac.o

ifndef KERNELSOURCE
$(warning WARNING: KERNELSOURCE undefined, using ${KERNELSOURCE})
endif

all: softmac_nullmac

softmac_nullmac:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
