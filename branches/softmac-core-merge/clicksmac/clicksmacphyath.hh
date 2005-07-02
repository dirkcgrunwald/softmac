#ifndef CLICK_CLICKSMACPHYATH_HH
#define CLICK_CLICKSMACPHYATH_HH
#include <click/element.hh>

#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "cu_softmac_api.h"
#include "cu_softmac_ath_api.h"
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>

#include "clicksmacphy.hh"

CLICK_DECLS

class ClickSMACPHYath : public Element, public ClickSMACPHY
{
public:
  
  ClickSMACPHYath();
  ~ClickSMACPHYath();
  
  const char *class_name() const	{ return "ClickSMACPHYath"; }
  const char *processing() const	{ return AGNOSTIC; }
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  void add_handlers();
  virtual void* cast(const char* name);
  
private:
  static String read_handler(Element *, void *);
  static int reset_handler(const String &, Element*, void*, ErrorHandler*);
  String _devname;
  struct net_device* _dev;
};

CLICK_ENDDECLS
#endif
