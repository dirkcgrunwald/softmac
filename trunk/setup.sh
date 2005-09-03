#modprobe softmac_rsmac
modprobe softmac_formagemac
echo multimac > /proc/softmac/create_instance
echo multi1 > /proc/softmac/insts/athphy0/mac_layer
echo 1 > /proc/softmac/insts/athphy0/raw_mode
echo formagemac > /proc/softmac/insts/multi1/addmaclayer
#echo rsmac > /proc/softmac/insts/multi1/addmaclayer
#echo athmac > /proc/softmac/insts/multi1/addmaclayer
iwconfig ath0 mode ad-hoc
iwconfig ath0 essid softmac
ifconfig multi1 hw ether `ifconfig ath0 | grep HWaddr | awk '{print $5}'`
