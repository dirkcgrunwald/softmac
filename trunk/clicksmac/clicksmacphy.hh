#ifndef CLICK_CLICKSMACPHY_HH
#define CLICK_CLICKSMACPHY_HH
#include <click/element.hh>
#include "cu_softmac_api.h"
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
  inline int TransmitPacket(Packet* p, int maxinflight);
  inline int TransmitPacketKeepOnFail(Packet* p, maxinflight);
  inline WritablePacket* CreatePacket(int size);
  inline void DestroyPacket(Packet* p);
  inline u_int32_t GetPacketTransmitDuration(Packet* p);
  inline u_int32_t GetTransmitLatency();
  inline void SetPacketRxSink(PacketEventSink* psink){_packetrxsink = psink};
  inline void SetPacketTxDoneSink(PacketEventSink* psink){_packettxdonesink = psink};
  inline u_int64_t GetTime();
  inline void SetTime(u_int64_t);

  class PacketEventSink {
  public:
    virtual void PacketEvent(Packet* p) = 0;
  };

protected:
  CU_SOFTMAC_PHYLAYER_INFO _phyinfo;
  CU_SOFTMAC_MACLAYER_INFO _macinfo;
  PacketEventSink* _packetrxsink;
  PacketEventSink* _packettxdonesink;

  // We implement static callbacks that act collectively as a shim SoftMAC MAC
  // that translates between Click and the SoftMAC PHY.
protected:
  static int cu_softmac_mac_packet_tx_done(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
  static int cu_softmac_mac_packet_rx(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
  static int cu_softmac_mac_work(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
  static int cu_softmac_mac_detach(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
  static int cu_softmac_mac_attach_to_phy(void*,CU_SOFTMAC_PHYLAYER_INFO*);
  static int cu_softmac_mac_detach_from_phy(void*);
  static int cu_softmac_mac_set_rx_func(void*,CU_SOFTMAC_MAC_RX_FUNC,void*);
  static int cu_softmac_mac_set_unload_notify_func(void*,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC,void*);

  // We keep a bank of "do nothing" functions around and
  // load them up into the appropriate _phyinfo elements instead
  // of null values on intialization.
  // This lets us avoid doing an "if null" check every time
  // we want to call one of the provided functions.
protected:
  static void cu_softmac_attach_mac(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo);
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

int
ClickSMACPHY::TransmitPacket(Packet* p,int maxinflight) {
  return (_phyinfo.cu_softmac_sendpacket)(_phyinfo.phyhandle,maxinflight,p->skb());
}

int
ClickSMACPHY::TransmitPacketKeepOnFail(Packet* p,int maxinflight) {
  return (_phyinfo.cu_softmac_sendpacket_keepskbonfail)(_phyinfo.phyhandle,maxinflight,p->skb());
}

WritablePacket*
ClickSMACPHY::CreatePacket(int size) {
  struct sk_buff* newskb = 0;
  Packet* newpacketro = 0;
  WritablePacket* newpacketrw = 0;

  // Use the phy layer packet create routine to make an skbuff
  // that will then get wrapped by a Click Packet object
  newskb = (_phyinfo.cu_softmac_alloc_skb)(_phyinfo.phyhandle,size);
  if (newskb) {
    newpacketro = Packet::make(newskb);
    if (newpacketro) {
      newpacketrw = newpacketro->uniqueify();
    }
  }

  return newpacketrw;
}

void
ClickSMACPHY::DestroyPacket(Packet* p) {
  (_phyinfo.cu_softmac_free_skb)(_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetPacketTransmitDuration(Packet* p) {
  return (_phyinfo.cu_softmac_get_duration)(_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetTransmitLatency() {
  return (_phyinfo.cu_softmac_get_txlatency)(_phyinfo.phyhandle);
}


////
//// SoftMAC MAC shim functions
////
int
ClickSMACPHY::cu_softmac_mac_packet_tx_done(CU_SOFTMAC_PHY_HANDLE ph,void* me,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY* obj = me;
  obj->_packettxdonesink->PacketEvent(Packet::make(thepacket));
}

int
ClickSMACPHY::cu_softmac_mac_packet_rx(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY* obj = me;
  obj->_packetrxsink->PacketEvent(Packet::make(thepacket));
}

int
ClickSMACPHY::cu_softmac_mac_work(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {  ClickSMACPHY* obj = me;
  // XXX do nothing right now -- may want to add a hook for this later
  return CU_SOFTMAC_MAC_NOTIFY_OK;
}

//
// Notification that the MAC layer is being detached from the PHY
//
int
ClickSMACPHY::cu_softmac_mac_detach(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {
  ClickSMACPHY* obj = me;
  // The phy layer is going away -- reset _phyinfo to "null"
  init_softmac_phyinfo(&obj->_phyinfo);
}

//
// Attach to a PHY layer
//
int
ClickSMACPHY::cu_softmac_mac_attach_to_phy(void* me,CU_SOFTMAC_PHYLAYER_INFO* phy) {
  ClickSMACPHY* obj = me;
}

//
// Detach from the current PHY layer
//
int
ClickSMACPHY::cu_softmac_mac_detach_from_phy(void* me) {
  ClickSMACPHY* obj = me;
}

//
// Set the function to call when receiving a packet.
// Not used in this iteration of the shim layer -- callback
// is handled directly using the packet notify thing.
//
int
ClickSMACPHY::cu_softmac_mac_set_rx_func(void* me,CU_SOFTMAC_MAC_RX_FUNC rxfunc,void* rxfuncpriv) {
}

//
// Set the function to call when we unload the MAC layer. Typically
// this is the higher level OS network layer abstraction. Not clear
// at moment if we'll be using this or not in this context...
//
int
ClickSMACPHY::cu_softmac_mac_set_unload_notify_func(void* me,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,void* unloadfuncpriv) {
}

////
//// Bank of "do nothing" PHY functions
////

void
ClickSMACPHY::cu_softmac_attach_mac(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo) {
  // Do nothing...
}

void
ClickSMACPHY::cu_softmac_detach_mac(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv) {
  // Do nothing...
}

u_int64_t
ClickSMACPHY::cu_softmac_get_time(CU_SOFTMAC_PHY_HANDLE nfh) {
  return 0;
}

void
ClickSMACPHY::cu_softmac_set_time(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time) {
  // Do nothing...
}

void
ClickSMACPHY::cu_softmac_schedule_work_asap(CU_SOFTMAC_PHY_HANDLE nfh) {
  // Do nothing...
}

struct sk_buff*
ClickSMACPHY::cu_softmac_alloc_skb(CU_SOFTMAC_PHY_HANDLE nfh,int datalen) {
  return 0;
}

void
ClickSMACPHY::cu_softmac_free_skb(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  
}

int
ClickSMACPHY::cu_softmac_sendpacket(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

int
ClickSMACPHY::cu_softmac_sendpacket_keepskbonfail(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

u_int32_t
ClickSMACPHY::cu_softmac_get_duration(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb) {
  return 0;
}

u_int32_t
ClickSMACPHY::cu_softmac_get_txlatency(CU_SOFTMAC_PHY_HANDLE nfh) {
  return 0;
}

//
// Set the phylayer info struct to contain our "null" functions
//
void
ClickSMACPHY::init_softmac_phyinfo(CU_SOFTMAC_PHYLAYER_INFO* pinfo) {
  memset(pinfo,0,sizeof(pinfo));
  pinfo->cu_softmac_attach_mac = cu_softmac_attach_mac;
  pinfo->cu_softmac_detach_mac = cu_softmac_detach_mac;
  pinfo->cu_softmac_get_time = cu_softmac_get_time;
  pinfo->cu_softmac_set_time = cu_softmac_set_time;
  pinfo->cu_softmac_schedule_work_asap = cu_softmac_schedule_work_asap;
  pinfo->cu_softmac_alloc_skb = cu_softmac_alloc_skb;
  pinfo->cu_softmac_free_skb = cu_softmac_free_skb;
  pinfo->cu_softmac_sendpacket = cu_softmac_sendpacket;
  pinfo->cu_softmac_sendpacket_keepskbonfail = cu_softmac_sendpacket_keepskbonfail;
  pinfo->cu_softmac_get_duration = cu_softmac_get_duration;
  pinfo->cu_softmac_get_txlatency = cu_softmac_get_txlatency;
  pinfo->phyhandle = 0;
}

CLICK_ENDDECLS
#endif
