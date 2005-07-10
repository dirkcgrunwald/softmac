#ifndef CLICK_SOFTMACMACLAYER_HH
#define CLICK_SOFTMACMACLAYER_HH
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

class SoftmacMACLayer {

public:
  SoftmacMACLayer();
  ~SoftmacMACLayer();

  /*
   * Base SoftMAC MAC layer functions.
   *
   */
public:
    
    // these simply call the C version of the interface.  
    // To override, set the _macinfo->cu_softmac_mac_* function pointers
    inline int PacketTX(struct sk_buff* thepacket, int intop) {
	click_chatter("softmacmaclayer::packettx");
	return (_macinfo->cu_softmac_mac_packet_tx)(_macinfo->mac_private,
						    thepacket, intop);
    };

    inline int AttachPHY(CU_SOFTMAC_PHYLAYER_INFO *phyinfo) {
	click_chatter("softmacmaclayer::attach");
	return (_macinfo->cu_softmac_mac_attach)(_macinfo->mac_private, phyinfo);
    };
    
    inline int DetachPHY() { 
	click_chatter("softmacmaclayer::detach");
	return (_macinfo->cu_softmac_mac_detach)(_macinfo->mac_private);
    };

    inline int Work(int intop) {
	return (_macinfo->cu_softmac_mac_work)(_macinfo->mac_private, intop);
    };
     
    class PacketEventSink {
    public:
	virtual void PacketEvent(Packet* p,int eventtype) = 0;
	enum {
	    RX = 0,
	    TXDONE = 1,
	};
    };
    
    void SetPacketRxSink(PacketEventSink* psink);
    void SetPacketTxDoneSink(PacketEventSink* psink);

    static SoftmacMACLayer* make(CU_SOFTMAC_MACLAYER_INFO *macinfo);
    static SoftmacMACLayer* make(const char *mac_instance_name);
    static SoftmacMACLayer* make();

    CU_SOFTMAC_MACLAYER_INFO *macinfo() { return _macinfo; };

    void get() { cu_softmac_macinfo_get(_macinfo); };
    void put() { cu_softmac_macinfo_free(_macinfo); };

    // This part of the class does the detail work involved in
    // interfacing with the softmac. If you don't care about
    // these details, then read no further.
protected:
    CU_SOFTMAC_MACLAYER_INFO* _macinfo;
    CU_SOFTMAC_MACLAYER_INFO* _defaultmac;

    SoftmacMACLayer::PacketEventSink* _packetrxsink;
    SoftmacMACLayer::PacketEventSink* _packettxdonesink;
    
    class PacketEventBlackHole : public PacketEventSink {
	virtual void PacketEvent(Packet* p, int etype) { p->kill(); };
    };
    PacketEventBlackHole _defaultsink;

    // CU_SOFTMAC_MACLAYER_INFO functions
    static int macinfo_packet_rx(void*, struct sk_buff* thepacket, int intop);
    static int macinfo_packet_tx_done(void*, struct sk_buff* thepacket, int intop);

    // setup macinfo with defaults.
    // this sets mac_private = me and sets the cu_softmac_mac_packet_tx_done and
    // cu_softmac_mac_packet_rx callbacks to use the PacketEventSink versions above
    static void macinfo_init(void *me, CU_SOFTMAC_MACLAYER_INFO* macinfo);
};


CLICK_ENDDECLS
#endif
