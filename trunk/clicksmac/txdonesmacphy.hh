#ifndef CLICK_TXDONESMACPHY_HH
#define CLICK_TXDONESMACPHY_HH

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

#include <click/element.hh>
#include "clicksmacphy.hh"
CLICK_DECLS

class TxDoneSMACPHY : public Element, public ClickSMACPHY::PacketEventSink
{
public:
  
  TxDoneSMACPHY();
  ~TxDoneSMACPHY();
    
  const char *class_name() const	{ return "TxDoneSMACPHY"; }
  const char *processing() const	{ return PUSH; }
    
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  
public:
  // TxDoneSMACPHY::PacketEventSink methods
  virtual void PacketEvent(Packet* p,int etype);

private:
  ClickSMACPHY* _smacphy;
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
