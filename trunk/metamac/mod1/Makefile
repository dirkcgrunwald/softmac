obj-m += softmac_multimac_mod1.o

ifndef KERNELSOURCE
$(warning WARNING: KERNELSOURCE undefined, using /usr/src/linux)
KERNELSOURCE=/usr/src/linux
endif

all: softmac_nullmac

softmac_nullmac:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
