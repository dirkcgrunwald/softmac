# every module should compile against this directory
ifndef KERNELSOURCE
$(warning WARNING: KERNELSOURCE undefined, using /usr/src/linux)
KERNELSOURCE=/usr/src/linux
export KERNELSOURCE
endif

SOFTMAC_ROOT=${PWD}/${DEPTH}
SOFTMAC_INCLUDES=-I${SOFTMAC_ROOT}/include -I${SOFTMAC_ROOT}/linux_netif -I${SOFTMAC_ROOT}/fec
EXTRA_CFLAGS = ${SOFTMAC_INCLUDES}

# make install will install modules to /lib/modules/VERSION/${INSTALL_MOD_DIR}
INSTALL_MOD_DIR = net
export INSTALL_MOD_DIR

linux_modules:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

linux_install:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules_install

linux_clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
