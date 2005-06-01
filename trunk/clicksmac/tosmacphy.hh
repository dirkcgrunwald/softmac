#ifndef CLICK_TOSMACPHY_HH
#define CLICK_TOSMACPHY_HH

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

class ToSMACPHY : public Element
{
public:
  
  ToSMACPHY();
  ~ToSMACPHY();
    
  const char *class_name() const	{ return "ToSMACPHY"; }
  const char *processing() const	{ return PUSH; }
    
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);

  void push(int port, Packet *);

private:
  ClickSMACPHY* _smacphy;
  int _maxinflight;
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
