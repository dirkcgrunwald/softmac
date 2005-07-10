#include <click/config.h>
#include <click/confparse.hh>
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

#include "softmac_phy.hh"

CLICK_DECLS

SoftmacPhy::SoftmacPhy()
    : Element(1, 1), _maxinflight(1)
{
    click_chatter("SoftmacPhy::SoftmacPhy()\n");
    _mac = 0;
    _phy = 0;
}

SoftmacPhy::~SoftmacPhy()
{
    click_chatter("~SoftmacPhy::SoftmacPhy()\n");
}

int
SoftmacPhy::configure(Vector<String> &conf, ErrorHandler *errh)
{
    click_chatter("SoftmacPhy::configure\n");

    if (cp_va_parse(conf, this, errh,
		    cpString, "phy name", &_phyname,
		    cpEnd) < 0)
	return -1;

    _phy = SoftmacPHYLayer::make(_phyname.cc());
    if (_phy) {
	_phy->get();
    } else {
	click_chatter("SoftmacPhy::configure phy error\n");
	return -1;
    }

    _mac = SoftmacMACLayer::make();
    if (_mac) {
	_mac->get();
    } else {
	_phy->put();
	_phy = 0;
	click_chatter("SoftmacPhy::configure mac error\n");
	return -1;
    }

    return 0;
}

int
SoftmacPhy::initialize(ErrorHandler *errh)
{
    click_chatter("SoftmacPhy::initialize\n");
    int error = 0;
    if (_mac && _phy) {
	_phy->AttachMAC(_mac->macinfo());
	_mac->AttachPHY(_phy->phyinfo());
	_mac->SetPacketRxSink(this);
    }
    return error;
}


void
SoftmacPhy::cleanup(CleanupStage stage)
{
    click_chatter("SoftmacPhy::cleanup\n");

    if (_phy) {
	_phy->DetachMAC();
	_phy->put();
    }
    if (_mac) {
	_mac->DetachPHY();
	_mac->put();
    }
}

String
SoftmacPhy::read_handler(Element *e, void *thunk)
{
    return "XXX implement this";
}

int
SoftmacPhy::reset_handler(const String &, Element *e, void *, ErrorHandler *)
{
    return 0;
}

void
SoftmacPhy::add_handlers()
{
}

void
SoftmacPhy::PacketEvent(Packet* p,int etype)
{
    click_chatter("SoftmacPhy::PacketEvent\n");
    output(0).push(p);
}

void
SoftmacPhy::push(int port, Packet *p)
{
    _phy->SendPacket(p, _maxinflight);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule)
EXPORT_ELEMENT(SoftmacPhy)
