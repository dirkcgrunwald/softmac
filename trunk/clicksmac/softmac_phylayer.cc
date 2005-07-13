/*
 * softmac_phylayer.{cc,hh} -- interface between CU SoftMAC API and Click
 * Michael Neufeld
 * Jeff Fifield
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

#include "softmac_phylayer.hh"

CLICK_DECLS

////
//// SoftmacPHYLayer implementation
////

SoftmacPHYLayer::SoftmacPHYLayer()
{
    click_chatter("SoftmacPHYLayer: constructor\n");

    _defaultphy = cu_softmac_phyinfo_alloc(); 
    _phyinfo = _defaultphy;
}

SoftmacPHYLayer::~SoftmacPHYLayer()
{
    click_chatter("SoftmacPHYLayer: destructor\n");
    cu_softmac_phyinfo_free(_defaultphy);
}

SoftmacPHYLayer*
SoftmacPHYLayer::make(CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    SoftmacPHYLayer *phy = 0;
    if (phyinfo) {
	phy = new SoftmacPHYLayer;
	if (phy)
	    phy->_phyinfo = phyinfo;
    }
    return phy;
}

SoftmacPHYLayer*
SoftmacPHYLayer::make(const char *phy_instance_name)
{
    CU_SOFTMAC_PHYLAYER_INFO *p = cu_softmac_phyinfo_get_by_name(phy_instance_name);
    SoftmacPHYLayer *phy = make(p);
    cu_softmac_phyinfo_free(p);
    return phy;
}

SoftmacPHYLayer*
SoftmacPHYLayer::make()
{
    SoftmacPHYLayer *phy = new SoftmacPHYLayer;
    return phy;
}

WritablePacket*
SoftmacPHYLayer::CreatePacket(int size) 
{
    struct sk_buff* newskb = 0;
    Packet* newpacketro = 0;
    WritablePacket* newpacketrw = 0;
    click_chatter("SoftmacPHYLayer: CreatePacket\n");
    // Use the phy layer packet create routine to make an skbuff
    // that will then get wrapped by a Click Packet object
    newskb = (_phyinfo->cu_softmac_phy_alloc_skb)(_phyinfo->phy_private,size);
    if (newskb) {
	newpacketro = Packet::make(newskb);
	if (newpacketro) {
	    newpacketrw = newpacketro->uniqueify();
	}
    }
    
    return newpacketrw;
}

void
SoftmacPHYLayer::DestroyPacket(Packet* p)
{
    click_chatter("SoftmacPHYLayer: DestroyPacket\n");
    (_phyinfo->cu_softmac_phy_free_skb)(_phyinfo->phy_private,p->skb());
}

u_int32_t
SoftmacPHYLayer::GetPacketTransmitDuration(Packet* p)
{
    click_chatter("SoftmacPHYLayer: GetTxDuration\n");
    return (_phyinfo->cu_softmac_phy_get_duration)(_phyinfo->phy_private,p->skb());
}

u_int32_t
SoftmacPHYLayer::GetTransmitLatency()
{
    return (_phyinfo->cu_softmac_phy_get_txlatency)(_phyinfo->phy_private);
}

CLICK_ENDDECLS
ELEMENT_PROVIDES(SoftmacPHYLayer)
