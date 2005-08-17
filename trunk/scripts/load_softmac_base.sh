#!/bin/sh

modprobe ath_pci

ifconfig ath0 up
iwconfig ath0 mode monitor
iwconfig ath0 channel 6

modprobe softmac_cheesymac
modprobe softmac_nullmac
modprobe softmac_multimac
modprobe softmac_remotemac
modprobe softmac_rawmac

echo athphy > /proc/softmac/create_instance
echo 1 > /proc/softmac/insts/athphy0/softmac_enable