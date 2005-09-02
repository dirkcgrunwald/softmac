
SUBDIRS=cheesymac \
	core \
	linux_netif \
	mactime \
	madwifi_bsd_phy \
	multimac \
	nullmac \
	rawmac \
	remotemac \
	remotemac/ktund \
	fec \
        formage

# every module should compile against this directory
ifndef KERNELSOURCE
$(warning WARNING: KERNELSOURCE undefined, using /usr/src/linux)
KERNELSOURCE=/usr/src/linux
export KERNELSOURCE
endif

# so that madwifi_bsd_phy can find the kernel tree
KERNELPATH=${KERNELSOURCE}
export KERNELPATH
# so that 'make install' works for madwifi_bsd_phy
KERNELRELEASE ?= $(shell echo -e 'foo:\n\t@echo \044(KERNELRELEASE)\ninclude Makefile' | make -C $(KERNELPATH) -s -f-)
export KERNELRELEASE

all:
	for dir in ${SUBDIRS}; do \
		(cd $$dir; ${MAKE} all) || exit 1; \
	done

install: all
	for dir in ${SUBDIRS}; do \
		(cd $$dir; ${MAKE} install) || exit 1; \
	done

clean:
	for dir in ${SUBDIRS}; do \
		(cd $$dir; ${MAKE} clean) || exit 1; \
	done
