#ifndef CLICK_CLICKSMACPHY_HH
#define CLICK_CLICKSMACPHY_HH
#include <click/element.hh>
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

class ClickSMACPHY {

public:
  ClickSMACPHY();
  ~ClickSMACPHY();

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

  // This opaque pointer is an attempt to limit dependencies on OS and SoftMAC
  // header files to clicksmacphy.cc and specific PHY layer classes.
  // Using this pointer does result in an
  // additional pointer indirection that could cause a slight performance
  // drop, though I haven't done any measurements to confirm or deny this.
  // If you're trying to really shave microseconds then it might be worth
  // your while to do some profiling and see if this abstraction is costing
  // more than you'd care to pay.
  ClickSMACPHY_glue* _softmac_glue;
};


CLICK_ENDDECLS
#endif
