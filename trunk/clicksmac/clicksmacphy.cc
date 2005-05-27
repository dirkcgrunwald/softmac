/*
 * clicksmacphy.{cc,hh} -- interface between CU SoftMAC API and Click
 *
 * Copyright (c) 2005 University of Colorado at Boulder
 *
 *  Permission to use, copy, modify, and distribute this software and its
 *  documentation for any purpose other than its incorporation into a
 *  commercial product is hereby granted without fee, provided that the
 *  above copyright notice appear in all copies and that both that
 *  copyright notice and this permission notice appear in supporting
 *  documentation, and that the name of the University not be used in
 *  advertising or publicity pertaining to distribution of the software
 *  without specific, written prior permission.
 *
 *  UNIVERSITY OF COLORADO DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 *  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
 *  FITNESS FOR ANY PARTICULAR PURPOSE.  IN NO EVENT SHALL THE UNIVERSITY
 *  OF COLORADO BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
 *  DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
 *  OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *  PERFORMANCE OF THIS SOFTWARE.
 *
 */

#include <click/config.h>
#include "clicksmacphy.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

class ClickSMACPHY_glue {

  friend class ClickSMACPHY;

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

////
//// ClickSMACPHY implementation
////

ClickSMACPHY::ClickSMACPHY()
  : Element(0, 0)
{
}

ClickSMACPHY::~ClickSMACPHY()
{
  // XXX build this
  // XXX also check on methods called at instance destruction...
}

int
ClickSMACPHY::configure(Vector<String> &conf, ErrorHandler *errh)
{
  if (cp_va_parse(conf, this, errh,
		  cpString, "SoftMAC PHY Type", &_phytype,
		  cpString, "SoftMAC PHY ID", &_phyid,
		  cpEnd) < 0)
    return -1;
  return 0;
}

String
ClickSMACPHY::read_handler(Element *e, void *thunk)
{
  // XXX build this
  return "TODO";
}

void
ClickSMACPHY::add_handlers()
{
  // XXX build this
}

int
ClickSMACPHY::TransmitPacket(Packet* p,int maxinflight) {
  return (_softmac_glue->_phyinfo.cu_softmac_sendpacket)(_softmac_glue->_phyinfo.phyhandle,maxinflight,p->skb());
}

int
ClickSMACPHY::TransmitPacketKeepOnFail(Packet* p,int maxinflight) {
  return (_softmac_glue->_phyinfo.cu_softmac_sendpacket_keepskbonfail)(_softmac_glue->_phyinfo.phyhandle,maxinflight,p->skb());
}

WritablePacket*
ClickSMACPHY::CreatePacket(int size) {
  struct sk_buff* newskb = 0;
  Packet* newpacketro = 0;
  WritablePacket* newpacketrw = 0;

  // Use the phy layer packet create routine to make an skbuff
  // that will then get wrapped by a Click Packet object
  newskb = (_softmac_glue->_phyinfo.cu_softmac_alloc_skb)(_softmac_glue->_phyinfo.phyhandle,size);
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
  (_softmac_glue->_phyinfo.cu_softmac_free_skb)(_softmac_glue->_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetPacketTransmitDuration(Packet* p) {
  return (_softmac_glue->_phyinfo.cu_softmac_get_duration)(_softmac_glue->_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetTransmitLatency() {
  return (_softmac_glue->_phyinfo.cu_softmac_get_txlatency)(_softmac_glue->_phyinfo.phyhandle);
}

void
ClickSMACPHY::SetPacketRxSink(PacketEventSink* psink) {
  _softmac_glue->_packetrxsink = psink;
}

void
ClickSMACPHY::SetPacketTxDoneSink(PacketEventSink* psink) {
  _softmac_glue->_packettxdonesink = psink;
}

////
//// ClickSMACPHY_glue implementation
//// SoftMAC MAC shim functions
////
int
ClickSMACPHY_glue::cu_softmac_mac_packet_tx_done(CU_SOFTMAC_PHY_HANDLE ph,void* me,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY_glue* obj = me;
  obj->_packettxdonesink->PacketEvent(Packet::make(thepacket));
}

int
ClickSMACPHY_glue::cu_softmac_mac_packet_rx(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY_glue* obj = me;
  obj->_packetrxsink->PacketEvent(Packet::make(thepacket));
}

int
ClickSMACPHY_glue::cu_softmac_mac_work(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {
  ClickSMACPHY_glue* obj = me;
  // XXX do nothing right now -- may want to add a hook for this later
  return CU_SOFTMAC_MAC_NOTIFY_OK;
}

//
// Notification that the MAC layer is being detached from the PHY
//
int
ClickSMACPHY_glue::cu_softmac_mac_detach(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {
  ClickSMACPHY_glue* obj = me;
  // The phy layer is going away -- reset _phyinfo to "null"
  init_softmac_phyinfo(&obj->_phyinfo);
}

//
// Attach to a PHY layer
//
int
ClickSMACPHY_glue::cu_softmac_mac_attach_to_phy(void* me,CU_SOFTMAC_PHYLAYER_INFO* phy) {
  ClickSMACPHY_glue* obj = me;
}

//
// Detach from the current PHY layer
//
int
ClickSMACPHY_glue::cu_softmac_mac_detach_from_phy(void* me) {
  ClickSMACPHY_glue* obj = me;
}

//
// Set the function to call when receiving a packet.
// Not used in this iteration of the shim layer -- callback
// is handled directly using the packet notify thing.
//
int
ClickSMACPHY_glue::cu_softmac_mac_set_rx_func(void* me,CU_SOFTMAC_MAC_RX_FUNC rxfunc,void* rxfuncpriv) {
  ClickSMACPHY_glue* obj = me;
}

//
// Set the function to call when we unload the MAC layer. Typically
// this is the higher level OS network layer abstraction. Not clear
// at moment if we'll be using this or not in this context...
//
int
ClickSMACPHY_glue::cu_softmac_mac_set_unload_notify_func(void* me,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,void* unloadfuncpriv) {
  ClickSMACPHY_glue* obj = me;
}

////
//// ClickSMACPHY_glue implementation
//// Bank of "do nothing" PHY functions
////

void
ClickSMACPHY_glue::cu_softmac_attach_mac(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo) {
  // Do nothing...
}

void
ClickSMACPHY_glue::cu_softmac_detach_mac(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv) {
  // Do nothing...
}

u_int64_t
ClickSMACPHY_glue::cu_softmac_get_time(CU_SOFTMAC_PHY_HANDLE nfh) {
  return 0;
}

void
ClickSMACPHY_glue::cu_softmac_set_time(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time) {
  // Do nothing...
}

void
ClickSMACPHY_glue::cu_softmac_schedule_work_asap(CU_SOFTMAC_PHY_HANDLE nfh) {
  // Do nothing...
}

struct sk_buff*
ClickSMACPHY_glue::cu_softmac_alloc_skb(CU_SOFTMAC_PHY_HANDLE nfh,int datalen) {
  return 0;
}

void
ClickSMACPHY_glue::cu_softmac_free_skb(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  
}

int
ClickSMACPHY_glue::cu_softmac_sendpacket(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

int
ClickSMACPHY_glue::cu_softmac_sendpacket_keepskbonfail(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) {
  // Free the packet if it's not null -- not technically "nothing" but
  // may prevent some memory leakage in corner cases.
  if (skb) {
    dev_kfree_skb_any(skb);
  }
  return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

u_int32_t
ClickSMACPHY_glue::cu_softmac_get_duration(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb) {
  return 0;
}

u_int32_t
ClickSMACPHY_glue::cu_softmac_get_txlatency(CU_SOFTMAC_PHY_HANDLE nfh) {
  return 0;
}

//
// Set the phylayer info struct to contain our "null" functions
//
void
ClickSMACPHY_glue::init_softmac_phyinfo(CU_SOFTMAC_PHYLAYER_INFO* pinfo) {
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
EXPORT_ELEMENT(EtherEncap)
