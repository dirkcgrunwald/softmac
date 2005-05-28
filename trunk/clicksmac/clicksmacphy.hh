#ifndef CLICK_CLICKSMACPHY_HH
#define CLICK_CLICKSMACPHY_HH
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

ClickSMACPHY()

=s encapsulation, Ethernet

Talks to SoftMAC PHY

=d

Longer description

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

class ClickSMACPHY {

public:
  ClickSMACPHY();
  ~ClickSMACPHY();

  /*
   * Base SoftMAC PHY layer functions.
   */
public:
  inline int TransmitPacket(Packet* p, int maxinflight) {
    return (_phyinfo.cu_softmac_sendpacket)(_phyinfo.phyhandle,maxinflight,p->skb());
  };

  inline int TransmitPacketKeepOnFail(Packet* p, int maxinflight) {
    return (_phyinfo.cu_softmac_sendpacket_keepskbonfail)(_phyinfo.phyhandle,maxinflight,p->skb());
  };

  inline WritablePacket* CreatePacket(int size);
  void DestroyPacket(Packet* p);
  u_int32_t GetPacketTransmitDuration(Packet* p);
  u_int32_t GetTransmitLatency();

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
  inline u_int64_t GetTime() { (_phyinfo.cu_softmac_get_time)(_phyinfo.phyhandle); };
  inline void SetTime(u_int64_t now) { (_phyinfo.cu_softmac_set_time)(_phyinfo.phyhandle,now); };

  // This part of the class does the detail work involved in
  // interfacing with the softmac. If you don't care about
  // these details, then read no further.
protected:
  CU_SOFTMAC_MACLAYER_INFO _macinfo;
  CU_SOFTMAC_PHYLAYER_INFO _phyinfo;
  ClickSMACPHY::PacketEventSink* _packetrxsink;
  ClickSMACPHY::PacketEventSink* _packettxdonesink;
  
  class PacketEventBlackHole : public PacketEventSink {
    virtual void PacketEvent(Packet* p, int etype) { p->kill(); };
  };
  // XXX this should be static -- see if compiler change fixes problem
  // with common vars
  PacketEventBlackHole _defaultsink;

  // We implement static callbacks that act collectively as a shim SoftMAC MAC
  // that translates between Click and the SoftMAC PHY.
public:
  static int cu_softmac_mac_packet_tx_done(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
  static int cu_softmac_mac_packet_rx(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
  static int cu_softmac_mac_work(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
  static int cu_softmac_mac_detach(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
  static int cu_softmac_mac_attach_to_phy(void*,CU_SOFTMAC_PHYLAYER_INFO*);
  static int cu_softmac_mac_detach_from_phy(void*);
  static int cu_softmac_mac_set_rx_func(void*,CU_SOFTMAC_MAC_RX_FUNC,void*);
  static int cu_softmac_mac_set_unload_notify_func(void*,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC,void*);
  static void init_softmac_macinfo(CU_SOFTMAC_MACLAYER_INFO* macinfo,ClickSMACPHY* macpriv);

  // We keep a bank of "do nothing" functions around and
  // load them up into the appropriate _phyinfo elements instead
  // of null values on intialization.
  // This lets us avoid doing an "if null" check every time
  // we want to call one of the provided functions.
protected:
  static int cu_softmac_attach_mac(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo);
  static void cu_softmac_detach_mac(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv);
  static u_int64_t cu_softmac_get_time(CU_SOFTMAC_PHY_HANDLE nfh);
  static void cu_softmac_set_time(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time);
  static void cu_softmac_schedule_work_asap(CU_SOFTMAC_PHY_HANDLE nfh);
  static struct sk_buff* cu_softmac_alloc_skb(CU_SOFTMAC_PHY_HANDLE nfh,int datalen);
  static void cu_softmac_free_skb(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff*);
  static int cu_softmac_sendpacket(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);
  static int cu_softmac_sendpacket_keepskbonfail(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);
  static u_int32_t cu_softmac_get_duration(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);
  static u_int32_t cu_softmac_get_txlatency(CU_SOFTMAC_PHY_HANDLE nfh);

  static void init_softmac_phyinfo(CU_SOFTMAC_PHYLAYER_INFO* pinfo);

};


CLICK_ENDDECLS
#endif
