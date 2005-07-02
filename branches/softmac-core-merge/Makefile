SUBDIRS=madwifi_bsd_phy linux_netif cheesymac core

install:
	@for dir in ${SUBDIRS}; do (cd $$dir; ${MAKE} install); done

clean:
	@for dir in ${SUBDIRS}; do (cd $$dir; ${MAKE} clean); done
