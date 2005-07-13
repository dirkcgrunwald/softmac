#ifndef CLICK_SOFTMACPHY_HH
#define CLICK_SOFTMACPHY_HH
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

#include "softmac_maclayer.hh"
#include "softmac_phylayer.hh"
CLICK_DECLS

/*
 * Softmac PHY layer element.
 *  input port 0 => phy tx
 *  phy rx => output port 0
 */

class SoftmacPhy : public Element, public SoftmacMACLayer::PacketEventSink
{
public:
    SoftmacPhy ();
    ~SoftmacPhy ();
  
    const char *class_name() const	{ return "SoftmacPhy"; }
    const char *processing() const	{ return AGNOSTIC; }
    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();
    void push(int port, Packet *p);

    void PacketEvent(Packet* p,int etype);

private:
    static String read_handler(Element *, void *);
    static int reset_handler(const String &, Element*, void*, ErrorHandler*);

    String _phyname;
    int _maxinflight;

    SoftmacPHYLayer *_phy;
    SoftmacMACLayer *_mac;
};

CLICK_ENDDECLS
#endif

