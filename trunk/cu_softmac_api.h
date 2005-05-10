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

#ifndef _CU_SOFTMAC_API_H
#define _CU_SOFTMAC_API_H

/** @file cu_softmac_api.h
 * @brief The main SoftMAC header file.
 *
 * This file includes definitions for the functions, types, and constants
 * used by MAC and PHY layers in the SoftMAC system.
 */

/*
**
**
** SoftMAC PHY Layer Functions
**
**
 */


/**
 * @brief Handle used by the specific PHY layer for its internal data
 */
typedef void* CU_SOFTMAC_PHY_HANDLE;

/**
 * @brief Forward declaration of the struct containing MAC layer information
 */
struct CU_SOFTMAC_MACLAYER_INFO_t;


/**
 * @brief Attach a MAC implementation to the softmac layer
 */
typedef void (*CU_SOFTMAC_PHY_ATTACH_MAC_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo);

/**
 * @brief Notify the PHY layer that the MAC layer is detaching
 *
 * Tell the softmac PHY that we are leaving the building. The semantics
 * of this call are such that *after* it returns the SoftMAC PHY won't
 * make any new calls into the MAC layer.
 */
typedef void (*CU_SOFTMAC_PHY_DETACH_MAC_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv);

/**
 * @brief Get the softmac time clock value
 *
 * This function is grouped with the PHY layer, even though it may
 * appear to be more of an OS-related function. However, some PHY layers
 * may have their own high-precision clocks that the MAC layer should
 * be using. For example, the Atheros PHY layer has such a clock.
 */
typedef u_int64_t (*CU_SOFTMAC_PHY_GET_TIME_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);
typedef void (*CU_SOFTMAC_PHY_SET_TIME_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time);

/**
 * @brief Request that the "work" method be called ASAP
 */
typedef void (*CU_SOFTMAC_PHY_SCHEDULE_WORK_ASAP_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);

/**
 * @brief Allocate an sk_buff for a packet
 *
 * This function allocates an sk_buff with sufficient space to hold <i> datalen
 * </i> bytes. This also includes sufficient headroom for whatever additional
 * headers the PHY layer may need to add as well as handling any special
 * alignment or location requirements for efficient transfer to hardware.
 * For example, the Atheros PHY layer requires five extra bytes at the
 * beginning of each packet to ensure data integrity and
 * cache-line alignment to ensure speedy DMA transfers.
 */
typedef struct sk_buff* (*CU_SOFTMAC_PHY_ALLOC_SKB_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int datalen);

/**
 * @brief Free an sk_buff (packet) either allocated by a call to
 * CU_SOFTMAC_PHY_ALLOC_SKB_FUNC or passed in from the PHY layer.
 */
typedef void (*CU_SOFTMAC_PHY_FREE_SKB_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff*);

/**
 * @brief Errors that might be returned from the send packet procedures
 */
enum {
  CU_SOFTMAC_PHY_SENDPACKET_OK = 0,
  CU_SOFTMAC_PHY_SENDPACKET_ERR_TOOMANYPENDING = -1000,
  CU_SOFTMAC_PHY_SENDPACKET_ERR_NETDOWN = -1001,
  CU_SOFTMAC_PHY_SENDPACKET_ERR_NOBUFFERS = -1002,
};

/**
 * @brief Send a packet, only permitting max_packets_inflight to be pending
 */
typedef int (*CU_SOFTMAC_PHY_SENDPACKET_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);

/*
 * @brief Send a packet, only permitting max_packets_inflight to be pending,
 * do NOT free the sk_buff upon failure.
 *
 * This allows callers to do things
 * like requeue a packet if they care to make another attempt to send the
 * packet that failed to go out.
 */
typedef int (*CU_SOFTMAC_PHY_SENDPACKET_KEEPSKBONFAIL_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb);

/**
 * @brief Take an ethernet-encapsulated packet and send it up the operating
 * system network protocol stack for this interface.
 *
 * XXX eventual goal is to allow a MAC layer to create
 * multiple network interfaces -- there's an implicit single
 * network interface associated with each PHY layer right now
 * due to the way the Atheros SoftMAC PHY works.
 */
typedef void (*CU_SOFTMAC_PHY_NETIF_RX_ETHER_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);

/**
 * @brief Ask the phy layer how long (in microseconds) it will take for this
 * packet to be transmitted, not including any initial transmit latency.
 */
typedef u_int32_t (*CU_SOFTMAC_PHY_GET_DURATION_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);

/**
 * @brief Ask the phy layer how much "lead time" there is between a request
 * to send a packet and the time it hits the air.
 */
typedef u_int32_t (*CU_SOFTMAC_PHY_GET_TXLATENCY_FUNC)(CU_SOFTMAC_PHY_HANDLE nfh);

/**
 * @brief Functions/variables exported by PHY layer.
 */
typedef struct {
  /**
   * @brief Attach a MAC layer to the PHY layer
   */
  CU_SOFTMAC_PHY_ATTACH_MAC_FUNC cu_softmac_attach_mac;
  /**
   * @brief Detach a MAC layer from the PHY layer
   */
  CU_SOFTMAC_PHY_DETACH_MAC_FUNC cu_softmac_detach_mac;
  /**
   * @brief Get current time
   */
  CU_SOFTMAC_PHY_GET_TIME_FUNC cu_softmac_get_time;
  /**
   * @brief Set current time
   */
  CU_SOFTMAC_PHY_SET_TIME_FUNC cu_softmac_set_time;
  /**
   * @brief Schedule the MAC layer <i>work</i> callback to be run
   * as soon as possible.
   */
  CU_SOFTMAC_PHY_SCHEDULE_WORK_ASAP_FUNC cu_softmac_schedule_work_asap;
  /**
   * @brief Allocate space for a packet.
   */
  CU_SOFTMAC_PHY_ALLOC_SKB_FUNC cu_softmac_alloc_skb;
  /**
   * @brief Free a packet.
   */
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

  CU_SOFTMAC_PHY_HANDLE phyhandle;
} CU_SOFTMAC_PHYLAYER_INFO;



/*
**
**
** SoftMAC MAC Layer Functions
**
**
 */

/**
 * @brief Notify the MAC layer that a packet-related event has occured.
 *
 * Multiple functions implemented by the PHY layer are of this type.
 */
typedef int (*CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC)(CU_SOFTMAC_PHY_HANDLE,void*,struct sk_buff* thepacket,int intop);
typedef int (*CU_SOFTMAC_MAC_NOTIFY_FUNC)(CU_SOFTMAC_PHY_HANDLE,void*,int intop);
typedef int (*CU_SOFTMAC_MAC_PHY_FUNC)(void*,CU_SOFTMAC_PHYLAYER_INFO*);
typedef int (*CU_SOFTMAC_MAC_SIMPLE_FUNC)(void*);
typedef int (*CU_SOFTMAC_MAC_INT_FUNC)(void*,int);
typedef int (*CU_SOFTMAC_MAC_PHY_INT_FUNC)(void*,CU_SOFTMAC_PHYLAYER_INFO*,int);

/**
 * @brief Status codes returned by the MAC layer when receiving
 * a notification from the SoftMAC PHY
 */
enum {
  /**
   * @brief Finished running, all is well
   */
  CU_SOFTMAC_MAC_NOTIFY_OK = 0,
  /**
   * @brief Finished for now, but schedule task to run again ASAP
   */
  CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN = 1,
  /**
   * @brief The MAC layer is busy and cannot take delivery of a packet.
   * The PHY layer should free the packet and continue.
   */
  CU_SOFTMAC_MAC_NOTIFY_BUSY = 2,
  /**
   * @brief The MAC layer is hosed. Free the packet and continue.
   */
  CU_SOFTMAC_MAC_NOTIFY_HOSED = 3,
};

/**
 * @brief Functions/data exported by a MAC layer implementation.
 */
typedef struct CU_SOFTMAC_MACLAYER_INFO_t {
  /**
   * @brief Called when an ethernet-encapsulated packet is ready to transmit.
   */
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_tx;
  /**
   * @brief Called when transmission of a packet is complete.
   */
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_tx_done;
  /**
   * @brief Called upon receipt of a packet.
   */
  CU_SOFTMAC_MAC_NOTIFY_PACKET_FUNC cu_softmac_mac_packet_rx;
  CU_SOFTMAC_MAC_NOTIFY_FUNC cu_softmac_mac_work;
  CU_SOFTMAC_MAC_NOTIFY_FUNC cu_softmac_mac_detach;
  CU_SOFTMAC_MAC_PHY_FUNC cu_softmac_mac_attach_to_phy;
  CU_SOFTMAC_MAC_SIMPLE_FUNC cu_softmac_mac_detach_from_phy;
  u_int32_t options;
  void* mac_private;
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

#endif
