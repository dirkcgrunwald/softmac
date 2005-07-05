obj-m += softmac_multimac.o

LINKS:=cu_softmac_api.h cu_softmac_ath_api.h softmac_netif.h
KERNELSOURCE=/usr/src/linux

install:
	@echo Checking for symlinks
	@for link in ${LINKS}; do \
		if [ -h $$link ]; then \
			(echo "Obmitting symlink") \
		else \
			(if [ $$link = "cu_softmac_api.h" ]; then \
				(ln -s ../$$link .) \
			elif [ $$link = "cu_softmac_ath_api.h" ]; then \
				(ln -s ../madwifi_bsd_phy/$$link .) \
			elif [ $$link = "softmac_netif.h" ]; then \
				(ln -s ../linux_netif/$$link .) \
			fi;) \
		fi; \
	done;
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} modules
	
clean:
	make -C ${KERNELSOURCE} SUBDIRS=${PWD} clean
	