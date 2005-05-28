#ifndef CLICK_FROMSMACPHY_HH
#define CLICK_FROMSMACPHY_HH
#include <click/element.hh>
#include "clicksmacphy.hh"
CLICK_DECLS

class FromSMACPHY : public Element, public ClickSMACPHY::PacketEventSink
{
public:
  
  FromSMACPHY();
  ~FromSMACPHY();
    
  const char *class_name() const	{ return "FromSMACPHY"; }
  const char *processing() const	{ return PUSH; }
    
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  
public:
  // ClickSMACPHY::PacketEventSink methods
  virtual void PacketEvent(Packet* p);

private:
  ClickSMACPHY* _smacphy;
  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
