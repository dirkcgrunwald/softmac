/*****************************************************************************
 *  Copyright 2005, Univerity of Colorado at Boulder.                        *
 *                                                                           *
 *                        All Rights Reserved                                *
 *                                                                           *
 *  Permission to use, copy, modify, and distribute this software and its    *
 *  documentation for any purpose other than its incorporation into a        *
 *  commercial product is hereby granted without fee, provided that the      *
 *  above copyright notice appear in all copies and that both that           *
 *  copyright notice and this permission notice appear in supporting         *
 *  documentation, and that the name of the University not be used in        *
 *  advertising or publicity pertaining to distribution of the software      *
 *  without specific, written prior permission.                              *
 *                                                                           *
 *  UNIVERSITY OF COLORADO DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS      *
 *  SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND        *
 *  FITNESS FOR ANY PARTICULAR PURPOSE.  IN NO EVENT SHALL THE UNIVERSITY    *
 *  OF COLORADO BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL         *
 *  DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA       *
 *  OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER        *
 *  TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR         *
 *  PERFORMANCE OF THIS SOFTWARE.                                            *
 *                                                                           * 
 ****************************************************************************/

/*
**
**
** SoftMAC PHY Layer Functions
**
**
 */


/*
 * Attach a MAC implementation to the softmac layer
 */
typedef void (*CU_SOFTMAC_PHY_ATTACH_MAC_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,CU_SOFTMAC_MACLAYER_INFO* cinfo);

/*
 * Tell the softmac PHY that we are leaving the building. The semantics
 * of this call are such that *after* it returns the SoftMAC PHY won't
 * make any new calls into the MAC layer.
 */
typedef void (*CU_SOFTMAC_PHY_DETACH_MAC_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv);

/*
 * Get/set the softmac time clock value
 */
typedef u_int64_t (*CU_SOFTMAC_PHY_GET_TIME_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);
typedef void (*CU_SOFTMAC_PHY_SET_TIME_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time);

/*
 * Request that the "work" method be called ASAP
 */
typedef void (*CU_SOFTMAC_PHY_SCHEDULE_WORK_ASAP_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);

/*
 * Alloc/free sk_buff for a packet
 */
typedef struct sk_buff* (*CU_SOFTMAC_PHY_ALLOC_SKB_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int datalen);
typedef void (*CU_SOFTMAC_PHY_FREE_SKB_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff*);

/*
 * Errors that might be returned from the send packet procedures
 */
enum {
  CU_SOFTMAC_PHY_SENDPACKET_ERR_TOOMANYPENDING = -1000,
  CU_SOFTMAC_PHY_SENDPACKET_ERR_NETDOWN = -1001,
  CU_SOFTMAC_PHY_SENDPACKET_ERR_NOBUFFERS = -1002,
};

/*
 * Send a packet, only permitting max_packets_inflight to be pending
 */
typedef int (*CU_SOFTMAC_PHY_SENDPACKET_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);

/*
 * Send a packet, only permitting max_packets_inflight to be pending.
 * Do NOT free the sk_buff upon failure. This allows callers to do things
 * like requeue a packet if they care to make another attempt to send the
 * packet that failed to go out.
 */
typedef int (*CU_SOFTMAC_PHY_SENDPACKET_KEEPSKBONFAIL_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);

/*
 * Take an ethernet-encapsulated packet and send it up the operating
 * system network protocol stack for this interface.
 * XXX eventual goal would be to allow a MAC layer to create
 * multiple network interfaces -- there's an implicit single
 * network interface associated with each phy layer right now
 * due to the way the Atheros softmac phy works.
 */
typedef void (*CU_SOFTMAC_PHY_NETIF_RX_ETHER_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);

/*
 * Ask the phy layer how long (in microseconds) it will take for this
 * packet to be transmitted, not including any initial tx latency
 */
typedef u_int32_t (*CU_SOFTMAC_PHY_GET_DURATION_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);

/*
 * Ask the phy layer how much "lead time" there is between a request
 * to send a packet and the time it hits the air.
 */
typedef u_int32_t (*CU_SOFTMAC_PHY_GET_TXLATENCY_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);
typedef void* CU_SOFTMAC_PHY_HANDLE;
/*
 * XXX add version id to this struct?
 */
typedef struct {
  /*
   * XXX
   * Add function pointers for generic functions listed here
   * and change names within if_ath.c to match, also
   * add function to fill in the appropriate function pointer
   * table. This will make life easier when doing multiple
   * MAC layers on top of a single PHY.
   */
  CU_SOFTMAC_PHY_ATTACH_MAC_FUNC cu_softmac_attach_mac;
  CU_SOFTMAC_PHY_DETACH_MAC_FUNC cu_softmac_detach_mac;
  CU_SOFTMAC_PHY_GET_TIME_FUNC cu_softmac_get_time;
  CU_SOFTMAC_PHY_SET_TIME_FUNC cu_softmac_set_time;
  CU_SOFTMAC_PHY_SCHEDULE_WORK_ASAP_FUNC cu_softmac_schedule_work_asap;
  CU_SOFTMAC_PHY_ALLOC_SKB_FUNC cu_softmac_alloc_skb;
  CU_SOFTMAC_PHY_FREE_SKB_FUNC cu_softmac_free_skb;
  CU_SOFTMAC_PHY_SENDPACKET_FUNC cu_softmac_sendpacket;
  CU_SOFTMAC_PHY_SENDPACKET_KEEPSKBONFAIL_FUNC cu_softmac_sendpacket_keepskbonfail;
  /*
   * XXX the cu_softmac_netif_rx_ether function is more related to the OS
   * than directly to the phy layer...
   */
  CU_SOFTMAC_PHY_NETIF_RX_ETHER_FUNC cu_softmac_netif_rx_ether;
  CU_SOFTMAC_PHY_GET_DURATION_FUNC cu_softmac_get_duration;
  CU_SOFTMAC_PHY_GET_TXLATENCY_FUNC cu_softmac_get_txlatency;

  CU_SOFTMAC_PHYHANDLE phyhandle;
} CU_SOFTMAC_PHYLAYER_INFO;



/*
**
**
** SoftMAC MAC Layer Functions
**
**
 */

typedef int (*CU_SOFTMAC_NOTIFY_PACKET_FUNC)(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
typedef int (*CU_SOFTMAC_MAC_NOTIFY_FUNC)(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
typedef int (*CU_SOFTMAC_MAC_PHY_FUNC)(void*,CU_SOFTMAC_PHYLAYER_INFO*);
/*
 * XXX add version id to this struct?
 */
typedef struct {
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_tx;
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_tx_done;
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_rx;
  CU_SOFTMAC_MAC_NOTIFY_FUNC cu_softmac_mac_work;
  CU_SOFTMAC_MAC_NOTIFY_FUNC cu_softmac_mac_detach;
  CU_SOFTMAC_MAC_CLIENT_PHY_FUNC cu_softmac_mac_attach_to_phy;
  u_int32_t options;
  void* client_private;
} CU_SOFTMAC_MACLAYER_INFO;

/*
 * We're also defining guidelines for "composable" MAC modules.
 * MAC modules that are "composable" need to export a couple of
 * key functions:
 *
 * 1) A "create_instance" function that takes a pointer to a "client_info"
 * structure and a CU_SOFTMAC_PHYLAYER_INFO and fills in appropriate values
 * for its notification functions and private data
 *
 * 2) A "set_cu_softmac_phylayer_info" function that sets the
 * CU_SOFTMAC_PHYLAYER_INFO that should be used by the MAC module
 * when accessing PHY layer softmac services.
 * 
 * In the initial iteration the "composite" MAC module will be assumed
 * to just "know" the names of these functions in the relevant MAC
 * layer modules and phy layers. Someone with more time/industry than
 * I've got right now could certainly make a "MAC broker" service that allowed
 * MAC layers to register and be referenced dynamically by some sort
 * of naming scheme by a composite MAC object.
 */

