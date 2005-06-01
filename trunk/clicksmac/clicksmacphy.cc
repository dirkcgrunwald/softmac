/*
 * clicksmacphy.{cc,hh} -- interface between CU SoftMAC API and Click
 * Michael Neufeld
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
#include <click/error.hh>
#include <click/glue.hh>

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

#include "clicksmacphy.hh"

CLICK_DECLS

////
//// ClickSMACPHY implementation
////

// XXX this should be static -- see if compiler change fixes problem
// with common vars
//static ClickSMACPHY::PacketEventBlackHole ClickSMACPHY::_defaultsink;

ClickSMACPHY::ClickSMACPHY() {
  click_chatter("ClickSMACPHY: constructor\n");
  init_softmac_phyinfo(&_phyinfo);
  init_softmac_macinfo(&_macinfo,this);
  _packetrxsink = &_defaultsink;
  _packettxdonesink = &_defaultsink;
}

ClickSMACPHY::~ClickSMACPHY() {
  click_chatter("ClickSMACPHY: destructor\n");
  cu_softmac_mac_detach_from_phy(this);
}

#if 0
int
ClickSMACPHY::TransmitPacket(Packet* p,int maxinflight) {
  return (_phyinfo.cu_softmac_sendpacket)(_phyinfo.phyhandle,maxinflight,p->skb());
}

int
ClickSMACPHY::TransmitPacketKeepOnFail(Packet* p,int maxinflight) {
  return (_phyinfo.cu_softmac_sendpacket_keepskbonfail)(_phyinfo.phyhandle,maxinflight,p->skb());
}
#endif

WritablePacket*
ClickSMACPHY::CreatePacket(int size) {
  struct sk_buff* newskb = 0;
  Packet* newpacketro = 0;
  WritablePacket* newpacketrw = 0;
  click_chatter("ClickSMACPHY: CreatePacket\n");
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
  click_chatter("ClickSMACPHY: DestroyPacket\n");
  (_phyinfo.cu_softmac_free_skb)(_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetPacketTransmitDuration(Packet* p) {
  click_chatter("ClickSMACPHY: GetTxDuration\n");
  return (_phyinfo.cu_softmac_get_duration)(_phyinfo.phyhandle,p->skb());
}

u_int32_t
ClickSMACPHY::GetTransmitLatency() {
  return (_phyinfo.cu_softmac_get_txlatency)(_phyinfo.phyhandle);
}

void
ClickSMACPHY::SetPacketRxSink(PacketEventSink* psink) {
  click_chatter("ClickSMACPHY: setting packetrx sink\n");
  _packetrxsink = psink;
}

void
ClickSMACPHY::SetPacketTxDoneSink(PacketEventSink* psink) {
  click_chatter("ClickSMACPHY: setting packet txdone sink\n");
  _packettxdonesink = psink;
}

//
// These are the "softmac detail" methods
//
int
ClickSMACPHY::cu_softmac_mac_packet_tx_done(CU_SOFTMAC_PHY_HANDLE ph,void* me,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY* obj = me;
  obj->_packettxdonesink->PacketEvent(Packet::make(thepacket),PacketEventSink::TXDONE);
  return CU_SOFTMAC_MAC_NOTIFY_OK;
}

int
ClickSMACPHY::cu_softmac_mac_packet_rx(CU_SOFTMAC_PHY_HANDLE ph,void* me,struct sk_buff* thepacket,int intop) {
  ClickSMACPHY* obj = me;
  obj->_packetrxsink->PacketEvent(Packet::make(thepacket),PacketEventSink::RX);
  return CU_SOFTMAC_MAC_NOTIFY_OK;
}

int
ClickSMACPHY::cu_softmac_mac_work(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {
  ClickSMACPHY* obj = me;
  // XXX do nothing right now -- may want to add a hook for this later
  return CU_SOFTMAC_MAC_NOTIFY_OK;
}

//
// Notification that the MAC layer is being detached from the PHY
//
int
ClickSMACPHY::cu_softmac_mac_detach(CU_SOFTMAC_PHY_HANDLE ph,void* me,int intop) {
  click_chatter("ClickSMACPHY: cu_softmac_mac_detach\n");
  ClickSMACPHY* obj = me;
  // The phy layer is going away -- reset _phyinfo to "null" state
  click_chatter("ClickSMACPHY: cu_softmac_mac_detach -- restting phyinfo\n");
  init_softmac_phyinfo(&obj->_phyinfo);
  return 0;
}

//
// Attach to a PHY layer
//
int
ClickSMACPHY::cu_softmac_mac_attach_to_phy(void* me,CU_SOFTMAC_PHYLAYER_INFO* phy) {
  ClickSMACPHY* obj = me;
  int result = 0;
  // XXX check to see if we're already attached to something?
  // XXX spinlock or something?
  memcpy(&obj->_phyinfo,phy,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
  click_chatter("ClickSMACPHY: attaching to PHY...\n");
  //init_softmac_macinfo(&obj->_macinfo,me);
  result = (obj->_phyinfo.cu_softmac_attach_mac)(obj->_phyinfo.phyhandle,&(obj->_macinfo));
  if (!result) {
    click_chatter("ClickSMACPHY: attached to PHY\n");
  }
  else {
    click_chatter("ClickSMACPHY: attach to PHY failed with %d!\n",result);
  }
  return result;
}

//
// Detach from the current PHY layer
//
int
ClickSMACPHY::cu_softmac_mac_detach_from_phy(void* me) {
  ClickSMACPHY* obj = me;
  int result = 0;

  click_chatter("ClickSMACPHY: detaching from PHY\n");
  (obj->_phyinfo.cu_softmac_detach_mac)(obj->_phyinfo.phyhandle,obj);
  click_chatter("ClickSMACPHY: returned from detach -- init phyinfo\n");
  init_softmac_phyinfo(&obj->_phyinfo);

  return result;
}

//
// Set the function to call when receiving a packet.
// Not used in this iteration of the shim layer -- callback
// is handled directly using the packet notify thing.
//
int
ClickSMACPHY::cu_softmac_mac_set_rx_func(void* me,CU_SOFTMAC_MAC_RX_FUNC rxfunc,void* rxfuncpriv) {
  ClickSMACPHY* obj = me;
  return 0;
}

//
// Set the function to call when we unload the MAC layer. Typically
// this is the higher level OS network layer abstraction. Not clear
// at moment if we'll be using this or not in this context...
//
int
ClickSMACPHY::cu_softmac_mac_set_unload_notify_func(void* me,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,void* unloadfuncpriv) {
  ClickSMACPHY* obj = me;
  return 0;
}

//
// Set the maclayer info struct to contain our shim functions
//
void
ClickSMACPHY::init_softmac_macinfo(CU_SOFTMAC_MACLAYER_INFO* macinfo,ClickSMACPHY* macpriv) {
  memset(macinfo,0,sizeof(macinfo));
  //macinfo->cu_softmac_mac_packet_tx = cu_softmac_mac_packet_tx_cheesymac;
  macinfo->cu_softmac_mac_packet_tx_done = cu_softmac_mac_packet_tx_done;
  macinfo->cu_softmac_mac_packet_rx = cu_softmac_mac_packet_rx;
  macinfo->cu_softmac_mac_work = cu_softmac_mac_work;
  macinfo->cu_softmac_mac_detach = cu_softmac_mac_detach;
  macinfo->cu_softmac_mac_attach_to_phy = cu_softmac_mac_attach_to_phy;
  macinfo->cu_softmac_mac_detach_from_phy = cu_softmac_mac_detach_from_phy;
  macinfo->cu_softmac_mac_set_rx_func = cu_softmac_mac_set_rx_func;
  macinfo->cu_softmac_mac_set_unload_notify_func = cu_softmac_mac_set_unload_notify_func;
  macinfo->mac_private = macpriv;
}


////
//// ClickSMACPHY implementation
//// Bank of "do nothing" PHY functions
////

int
ClickSMACPHY::cu_softmac_attach_mac(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo) {
  // Do nothing...
  click_chatter("ClickSMACPHY: dummy attach_mac!\n");
  return -1;
}

void
ClickSMACPHY::cu_softmac_detach_mac(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv) {
  click_chatter("ClickSMACPHY: dummy detach_mac!\n");
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
ELEMENT_PROVIDES(ClickSMACPHY)
