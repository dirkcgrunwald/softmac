typedef void* CU_SOFTMAC_NETIFHANDLE;
typedef int (*CU_SOFTMAC_NOTIFY_PACKET_FUNC)(CU_SOFTMAC_NETIFHANDLE,void*,struct sk_buff* thepacket,int intop);
typedef int (*CU_SOFTMAC_NOTIFY_FUNC)(CU_SOFTMAC_NETIFHANDLE,void*,int intop);
typedef struct {
  CU_SOFTMAC_NOTIFY_PACKET_FUNC cu_softmac_packet_tx;
  CU_SOFTMAC_NOTIFY_PACKET_FUNC cu_softmac_packet_tx_done;
  CU_SOFTMAC_NOTIFY_PACKET_FUNC cu_softmac_packet_rx;
  CU_SOFTMAC_NOTIFY_FUNC cu_softmac_work;
  CU_SOFTMAC_NOTIFY_FUNC cu_softmac_detach;
  u_int32_t options;
  void* client_private;
} CU_SOFTMAC_CLIENT_INFO;
enum {
  /*
   * Special options for deferring RX and TXDONE because
   * we can opt to defer *all* handling of packet rx and
   * txdone interrupts until the bottom half. We can also
   * rig things such that the basic DMA transfer/ring buffer
   * maintenance occurs in the top half, allowing the MAC layer
   * to decide on a packet-per-packet basis whether or not further
   * work will be deferred until the bottom half.
   */
  CU_SOFTMAC_DEFER_ALL_RX =     0x00000001,
  CU_SOFTMAC_DEFER_ALL_TXDONE = 0x00000002,

  /*
   * Optionally allow packets that fail the 802.11 CRC error check
   * through. Some MAC implementations may not want to worry about
   * packet corruption and explicitly do NOT want to get packets
   * with CRC errors, others may want them.
   */
  CU_SOFTMAC_ALLOW_CRCERR = 0x00000004,
};

/*
 * Attach a MAC implementation to the softmac layer
 */
CU_SOFTMAC_NETIFHANDLE cu_softmac_attach(struct net_device* dev,CU_SOFTMAC_CLIENT_INFO* cinfo);

/*
 * Tell the softmac PHY that we are leaving the building. The semantics
 * of this call are such that *after* it returns the SoftMAC PHY won't
 * make any new calls into the MAC layer.
 */
void cu_softmac_detach_mac(CU_SOFTMAC_NETIFHANDLE nfh,void* mypriv);

/*
 * Get/set the softmac time clock value
 */
u_int64_t cu_softmac_get_time(CU_SOFTMAC_NETIFHANDLE nfh);
void cu_softmac_set_time(CU_SOFTMAC_NETIFHANDLE nfh,u_int64_t time);

/*
 * Request that the "work" method be called ASAP
 */
void cu_softmac_schedule_work_asap(CU_SOFTMAC_NETIFHANDLE nfh);
enum {
  CU_SOFTMAC_SENDPACKET_ERR_TOOMANYPENDING = -1000,
  CU_SOFTMAC_SENDPACKET_ERR_NETDOWN = -1001,
  CU_SOFTMAC_SENDPACKET_ERR_NOBUFFERS = -1002,
};
struct sk_buff* cu_softmac_alloc_skb(CU_SOFTMAC_NETIFHANDLE nfh,int datalen);
void cu_softmac_free_skb(CU_SOFTMAC_NETIFHANDLE nfh,struct sk_buff*);
int cu_softmac_sendpacket(CU_SOFTMAC_NETIFHANDLE nfh,
			  int max_packets_inflight,
			  struct sk_buff* skb);
int cu_softmac_sendpacket_keepskbonfail(CU_SOFTMAC_NETIFHANDLE nfh,
					int max_packets_inflight,
					struct sk_buff* skb);
/*
 * Send an ethernet-encapsulated packet up the stack to the OS
 */
void cu_softmac_netif_rx_ether(CU_SOFTMAC_NETIFHANDLE nfh,
			       struct sk_buff* skb);

typedef CU_SOFTMAC_NETIFHANDLE (*CU_SOFTMAC_ATTACH_MAC_FUNC)(struct net_device* dev,CU_SOFTMAC_CLIENT_INFO* cinfo);
typedef void (*CU_SOFTMAC_DETACH_MAC_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,void* mypriv);
typedef u_int64_t (*CU_SOFTMAC_GET_TIME_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh);
typedef void (*CU_SOFTMAC_SET_TIME_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,u_int64_t time);
typedef void (*CU_SOFTMAC_SCHEDULE_WORK_ASAP_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh);
typedef struct sk_buff* (*CU_SOFTMAC_ALLOC_SKB_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,int datalen);
typedef void (*CU_SOFTMAC_FREE_SKB_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,struct sk_buff*);
typedef int (*CU_SOFTMAC_SENDPACKET_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,int max_packets_inflight,struct sk_buff* skb);
typedef int (*CU_SOFTMAC_SENDPACKET_KEEPSKBONFAIL_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,int max_packets_inflight,struct sk_buff* skb);
typedef void (*CU_SOFTMAC_NETIF_RX_ETHER_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,struct sk_buff* skb);
typedef u_int32_t (*CU_SOFTMAC_GET_DURATION_FUNC)(CU_SOFTMAC_NETIFHANDLE nfh,struct sk_buff* skb);

typedef struct {
  /*
   * XXX
   * Add function pointers for generic functions listed here
   * and change names within if_ath.c to match, also
   * add function to fill in the appropriate function pointer
   * table. This will make life easier when doing multiple
   * MAC layers on top of a single PHY.
   */

  CU_SOFTMAC_ATTACH_MAC_FUNC cu_softmac_attach_mac;
  CU_SOFTMAC_DETACH_MAC_FUNC cu_softmac_detach_mac;
  CU_SOFTMAC_GET_TIME_FUNC cu_softmac_get_time;
  CU_SOFTMAC_SET_TIME_FUNC cu_softmac_set_time;
  CU_SOFTMAC_SCHEDULE_WORK_ASAP_FUNC cu_softmac_schedule_work_asap;
  CU_SOFTMAC_ALLOC_SKB_FUNC cu_softmac_alloc_skb;
  CU_SOFTMAC_FREE_SKB_FUNC cu_softmac_free_skb;
  CU_SOFTMAC_SENDPACKET_FUNC cu_softmac_sendpacket;
  CU_SOFTMAC_SENDPACKET_KEEPSKBONFAIL_FUNC cu_softmac_sendpacket_keepskbonfail;
  CU_SOFTMAC_NETIF_RX_ETHER_FUNC cu_softmac_netif_rx_ether;
  CU_SOFTMAC_GET_DURATION_FUNC cu_softmac_get_duration;

  CU_SOFTMAC_NETIFHANDLE phyhandle;
} CU_SOFTMAC_PHYLAYER_INFO;

/*
 * The Atheros driver doesn't really offer enough direct control
 * of the PHY layer to permit a MAC layer to do its own PHY CCA,
 * backoff and such. So, we let the MAC layer control some of
 * the CSMA properties performed by the underlying system.
 * XXX move these to the atheros-specific header file!
 *
 */

void cu_softmac_ath_set_cca_nf(CU_SOFTMAC_NETIFHANDLE nfh,
			   u_int32_t ccanf);
void cu_softmac_ath_set_cw(CU_SOFTMAC_NETIFHANDLE nfh,int cwmin,int cwmax);
u_int32_t cu_softmac_ath_get_slottime(CU_SOFTMAC_NETIFHANDLE nfh);
void cu_softmac_ath_set_slottime(CU_SOFTMAC_NETIFHANDLE nfh,u_int32_t slottime);
void cu_softmac_ath_set_options(CU_SOFTMAC_NETIFHANDLE nfh,u_int32_t options);

/*
 * Per-packet phy layer directives are set in the skbuff, as
 * are some phy layer properties upon reception.
 * These routines manipulate/query these directives.
 * XXX unclear if these should be in Atheros-specific
 * header or not?
 *
 */
void cu_softmac_ath_set_default_phy_props(CU_SOFTMAC_NETIFHANDLE nfh,
					  struct sk_buff* packet);

void cu_softmac_ath_set_tx_bitrate(CU_SOFTMAC_NETIFHANDLE nfh,
				   struct sk_buff* packet,unsigned char rate);

unsigned char cu_softmac_ath_get_rx_bitrate(CU_SOFTMAC_NETIFHANDLE,
					    struct sk_buff* packet);

void cu_softmac_ath_require_txdone_interrupt(CU_SOFTMAC_NETIFHANDLE nfh,
					     struct sk_buff* packet,
					     int require_interrupt);

u_int64_t cu_softmac_ath_get_rx_time(CU_SOFTMAC_NETIFHANDLE nfh,
				     struct sk_buff* packet);

int cu_softmac_ath_has_rx_crc_error(CU_SOFTMAC_NETIFHANDLE nfh,
				    struct sk_buff* packet);

/*
 * We're also defining guidelines for "composable" MAC modules.
 * MAC modules that are "composable" need to export a couple of
 * key functions:
 *
 * 1) A "create_instance" function that takes a pointer to a "client_info"
 * structure and a CU_SOFTMAC_NETIFHANDLE and fills in appropriate values
 * for its notification functions and private data
 *
 * 2) A "set_cu_softmac_netifhandle" function that sets the
 * CU_SOFTMAC_NETIFHANDLE that should be used by the MAC module
 * when accessing PHY layer softmac services.
 * 
 * In the initial iteration the "composite" MAC module will be assumed
 * to just "know" the names of these functions in the relevant MAC
 * layer modules. Someone with more time/industry than I've got right
 * now could certainly make a "MAC broker" service that allowed
 * MAC layers to register and be referenced dynamically by some sort
 * of naming scheme by a composite MAC object.
 */
