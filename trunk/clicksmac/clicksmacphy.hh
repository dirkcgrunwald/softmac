#ifndef CLICK_CLICKSMACPHY_HH
#define CLICK_CLICKSMACPHY_HH
#include <click/element.hh>
#include "cu_softmac_api.h"
CLICK_DECLS

/*
=c

ClickSMACPHY()

=s encapsulation, Ethernet

Talks to SoftMAC PHY

=d

Longer description

=e

Example

=n

Note

=h handler

A handler

=h handler2

A second handler

=a

See also... */

class ClickSMACPHY_glue;

class ClickSMACPHY : public Element {

public:
  ClickSMACPHY();
  ~ClickSMACPHY();

  const char *class_name() const	{ return "ClickSMACPHY"; }
  const char *processing() const	{ return AGNOSTIC; }
  
  int configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const	{ return true; }
  void add_handlers();

  /*
   * Base SoftMAC PHY layer functions.
   */
public:
  inline int TransmitPacket(Packet* p, int maxinflight);
  inline int TransmitPacketKeepOnFail(Packet* p, maxinflight);
  inline WritablePacket* CreatePacket(int size);
  inline void DestroyPacket(Packet* p);
  inline u_int32_t GetPacketTransmitDuration(Packet* p);
  inline u_int32_t GetTransmitLatency();
  inline void SetPacketRxSink(PacketEventSink* psink);
  inline void SetPacketTxDoneSink(PacketEventSink* psink);
  inline u_int64_t GetTime();
  inline void SetTime(u_int64_t);

  class PacketEventSink {
  public:
    virtual void PacketEvent(Packet* p) = 0;
  };
  
protected:
  String _phytype;
  String _phyid;

  // This is an attempt to limit dependencies on OS and SoftMAC
  // header files to clicksmacphy.cc.
  ClickSMACPHY_glue* _softmac_glue;
};


CLICK_ENDDECLS
#endif
