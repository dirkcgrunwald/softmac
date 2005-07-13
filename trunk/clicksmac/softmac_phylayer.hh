#ifndef CLICK_SOFTMACPHYLAYER_HH
#define CLICK_SOFTMACPHYLAYER_HH
#include <click/element.hh>

#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "cu_softmac_api.h"
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>

CLICK_DECLS

/*
=c

SoftmacPHYLayer()

=s encapsulation, Ethernet

Click SoftMAC PHY interface

=d

SoftmacPHYLayer wraps a SoftMAC PHY

=e

Example

=n

Note

=h handler

A handler

=h handler2

A second handler

=a

See also... */

class SoftmacPHYLayer {

public:
  SoftmacPHYLayer();
  ~SoftmacPHYLayer();

  /*
   * Base SoftMAC PHY layer functions.
   */
public:

    inline int AttachMAC(CU_SOFTMAC_MACLAYER_INFO *macinfo) {
	return (_phyinfo->cu_softmac_phy_attach)(_phyinfo->phy_private, macinfo);
    }
    
    inline void DetachMAC() { 
	(_phyinfo->cu_softmac_phy_detach)(_phyinfo->phy_private);
    }
    
    inline u_int64_t GetTime() { 
	return (_phyinfo->cu_softmac_phy_get_time)(_phyinfo->phy_private); };
    
    inline void SetTime(u_int64_t now) { 
	(_phyinfo->cu_softmac_phy_set_time)(_phyinfo->phy_private,now); };
    
    inline void ScheculeWorkASAP() { 
	(_phyinfo->cu_softmac_phy_schedule_work_asap)(_phyinfo->phy_private); };

    inline WritablePacket* CreatePacket(int size);
    void DestroyPacket(Packet* p);

    inline int SendPacket(Packet* p, int maxinflight) {
	return (_phyinfo->cu_softmac_phy_sendpacket)(_phyinfo->phy_private,maxinflight,p->skb());
    };
    
    inline int SendPacketKeepOnFail(Packet* p, int maxinflight) {
	return (_phyinfo->cu_softmac_phy_sendpacket_keepskbonfail)(_phyinfo->phy_private,
								   maxinflight,
								   p->skb());
    };

    u_int32_t GetPacketTransmitDuration(Packet* p);
    u_int32_t GetTransmitLatency();

    static SoftmacPHYLayer* make(CU_SOFTMAC_PHYLAYER_INFO *phyinfo);
    static SoftmacPHYLayer* make(const char *phy_instance_name);
    static SoftmacPHYLayer* make();

    CU_SOFTMAC_PHYLAYER_INFO *phyinfo() { return _phyinfo; }

    void get() { cu_softmac_phyinfo_get(_phyinfo); }
    void put() { cu_softmac_phyinfo_free(_phyinfo); }
    // This part of the class does the detail work involved in
    // interfacing with the softmac. If you don't care about
    // these details, then read no further.
protected:
    CU_SOFTMAC_PHYLAYER_INFO* _phyinfo;
    CU_SOFTMAC_PHYLAYER_INFO* _defaultphy;

    static void phyinfo_init(void *me, CU_SOFTMAC_PHYLAYER_INFO* phyinfo);
};


CLICK_ENDDECLS
#endif
