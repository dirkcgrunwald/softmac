
SOFTMAC_ROOT=${PWD}/${DEPTH}
SOFTMAC_INCLUDES=-I${SOFTMAC_ROOT}/include -I${SOFTMAC_ROOT}/linux_netif
EXTRA_CFLAGS = ${SOFTMAC_INCLUDES}

# make install will install modules to /lib/modules/VERSION/${INSTALL_MOD_DIR}
INSTALL_MOD_DIR = net
export INSTALL_MOD_DIR

modules:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules

install:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules_install

clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
