#ifndef CLICK_CLICKSMACPHYGLUE_HH
#define CLICK_CLICKSMACPHYGLUE_HH
#include <click/element.hh>
#include "cu_softmac_api.h"
CLICK_DECLS

class ClickSMACPHYglue {

  friend class ClickSMACPHY;
public:
  ClickSMACPHYglue();
  ~ClickSMACPHYglue();
  // XXX maybe make this protected and require access to it through
  // a spinlock? Should think about this...
  CU_SOFTMAC_MACLAYER_INFO _macinfo;

protected:
  CU_SOFTMAC_PHYLAYER_INFO _phyinfo;
  ClickSMACPHY::PacketEventSink* _packetrxsink;
  ClickSMACPHY::PacketEventSink* _packettxdonesink;

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
  static void init_softmac_macinfo(CU_SOFTMAC_MACLAYER_INFO* macinfo,ClickSMACPHYglue* macpriv);

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
