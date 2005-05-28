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

#include "clicksmacphy.hh"
#include "txdonesmacphy.hh"
CLICK_DECLS

TxDoneSMACPHY::TxDoneSMACPHY()
  : Element(0, 1), _smacphy(0)
{
}

TxDoneSMACPHY::~TxDoneSMACPHY()
{
}

int
TxDoneSMACPHY::configure(Vector<String> &conf, ErrorHandler *errh)
{
  Element* smacel;
  if (cp_va_parse(conf, this, errh,
		  cpElement, "SoftMAC PHY element", smacel,
		  cpEnd) < 0)
    return -1;
  
  if (smacel) {
    _smacphy = smacel->cast("ClickSMACPHY");
  }

  if (!_smacphy) {
    // XXX make up an error code/string!
    return -1;
  }

  return 0;
}

int
TxDoneSMACPHY::initialize(ErrorHandler *errh)
{
  // XXX finish this
  _smacphy->SetPacketTxDoneSink(this);
  return 0;
}

// ClickSMACPHY::PacketEventSink methods
void
TxDoneSMACPHY::PacketEvent(Packet* p,int etype) {
  output(0).push(p);
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(linuxmodule ClickSMACPHY)
EXPORT_ELEMENT(TxDoneSMACPHY)
