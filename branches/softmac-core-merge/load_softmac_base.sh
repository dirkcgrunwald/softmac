#!/bin/sh
modprobe ath_pci
iwconfig ath0 mode monitor
iwconfig ath0 channel 1
echo 1 >/proc/sys/dev/ath0/cu_softmac
ifconfig ath0 up
insmod ./linux_netif/softmac_netif.ko

