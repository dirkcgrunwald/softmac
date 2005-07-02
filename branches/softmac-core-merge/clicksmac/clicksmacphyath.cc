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
#include "cu_softmac_ath_api.h"
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>


#include "clicksmacphy.hh"
#include "clicksmacphyath.hh"

CLICK_DECLS

ClickSMACPHYath::ClickSMACPHYath()
  : Element(0, 0),_dev(0)
{
    //MOD_INC_USE_COUNT;
}

ClickSMACPHYath::~ClickSMACPHYath()
{
    //MOD_DEC_USE_COUNT;
}

int
ClickSMACPHYath::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (cp_va_parse(conf, this, errh,
		    cpString, "device name", &_devname,
		    cpEnd) < 0)
	return -1;
    _dev = dev_get_by_name(_devname.cc());
    if (!_dev) {
      return -1;
    }
    return 0;
}

int
ClickSMACPHYath::initialize(ErrorHandler *errh)
{
  int error = 0;

  CU_SOFTMAC_PHYLAYER_INFO athphyinfo = {0,};

  //_dev = dev_get_by_name(_devname.cc());
  if (_dev) {
    int attachres = 0;
    // Grab atheros phy info and attach it to our mac layer
    cu_softmac_ath_get_phyinfo(_dev,&athphyinfo);
    click_chatter("ClickSMACPHYath: About to attach to phy...\n");
    attachres = (_macinfo.cu_softmac_mac_attach_to_phy)((ClickSMACPHY*)this,&athphyinfo);
    if (attachres) {
      click_chatter("ClickSMACPHYath: got %d from attach\n",attachres);
    }
    else {
      click_chatter("ClickSMACPHYath: got %d from attach\n",attachres);
    }
  }
  else {
    error = errh->error("unable to find device %s", _devname.cc());
  }
  return error;
}

void
ClickSMACPHYath::cleanup(CleanupStage stage)
{
  click_chatter("ClickSMACPHYath: cleanup -- detach from phy\n");
  (_macinfo.cu_softmac_mac_detach_from_phy)(_macinfo.mac_private);
  if (_dev) {
    dev_put(_dev);
    _dev = 0;
  }
}

String
ClickSMACPHYath::read_handler(Element *e, void *thunk)
{
  return "XXX implement this";
}

int
ClickSMACPHYath::reset_handler(const String &, Element *e, void *, ErrorHandler *)
{
    return 0;
}

void
ClickSMACPHYath::add_handlers()
{
  // XXX implement this
}

void*
ClickSMACPHYath::cast(const char* name) {
  if (strcmp(name,"ClickSMACPHYath")) {
    return ((ClickSMACPHYath*) this);
  }
  else if (strcmp(name,"ClickSMACPHY")) {
    return ((ClickSMACPHY*) this);
  }
  else {
    return 0;
  }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule ClickSMACPHY)
EXPORT_ELEMENT(ClickSMACPHYath)
