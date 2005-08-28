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
#ifndef _CU_SOFTMAC_ATH_API_H
#define _CU_SOFTMAC_ATH_API_H

#include "cu_softmac_api.h"

/*
 * The Atheros driver doesn't really offer enough direct control
 * of the PHY layer to permit a MAC layer to do its own PHY CCA,
 * backoff and such. So, we let the MAC layer control some of
 * the CSMA properties performed by the underlying system.
 */

void cu_softmac_ath_set_cca_nf(void* mydata, u_int32_t ccanf);
void cu_softmac_ath_set_cw(void* mydata, int cwmin, int cwmax);
u_int32_t cu_softmac_ath_get_slottime(void* mydata);
void cu_softmac_ath_set_slottime(void* mydata, u_int32_t slottime);
void cu_softmac_ath_set_options(void* mydata, u_int32_t options);

/*
 * Per-packet phy layer directives are set in the skbuff, as
 * are some phy layer properties upon reception.
 * These routines manipulate/query these directives.
 */

/*
 * XXX unclear if these should be in Atheros-specific
 * header or not? Some of these could be abstracted
 * away as a "simple" PHY encoding interface that
 * could be applicable for multiple PHY layers.
 *
 */
void cu_softmac_ath_set_default_phy_props(void* mydata, struct sk_buff* packet);

/* set the bitrate 'packet' should be sent with */
void cu_softmac_ath_set_tx_bitrate(void* mydata,
				   struct sk_buff* packet,
				   unsigned char rate);

/* return the bitrate 'packet' was received with */
u_int8_t cu_softmac_ath_get_rx_bitrate(void* mydata, struct sk_buff* packet);

/* request a txdone interrupt for this packet */
void cu_softmac_ath_require_txdone_interrupt(void* mydata, 
					     struct sk_buff* packet,
					     int require_interrupt);

/* return the 64-bit receive timestamp */
u_int64_t cu_softmac_ath_get_rx_time(void* mydata, struct sk_buff* packet);

/* return the signal strength 'packet' was received with */
u_int8_t cu_softmac_ath_get_rx_rssi(void* mydata, struct sk_buff* packet);

/* return the channel 'packet' was recieved on */
u_int8_t cu_softmac_ath_get_rx_channel(void* mydata, struct sk_buff* packet);

/* return 1 if 'packet' containes a crc error */
u_int8_t cu_softmac_ath_has_rx_crc_error(void* mydata, struct sk_buff* packet);

/* set the antenna configuration to 'state' when transmitting 'packet' */
void cu_softmac_ath_set_tx_antenna(void *mydata, struct sk_buff* packet, u_int32_t state);

/* return the configuration the antenna had when 'packet' was received */
u_int32_t cu_softmac_ath_get_rx_antenna(void *mydata, struct sk_buff* packet);

/* return 1 if the packet is of the atheros softmac variety */
int cu_softmac_ath_issoftmac(/*struct ath_softc**/void *sc, struct sk_buff* skb);

/* perform atheros softmac packet decapsulation */
struct sk_buff* cu_softmac_ath_decapsulate(/*struct ath_softc**/void *sc,struct sk_buff* skb);

/* perform atheros softmac packet decapsulation */
struct sk_buff* cu_softmac_ath_encapsulate(/*struct ath_softc**/void *sc,struct sk_buff* skb);

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
  CU_SOFTMAC_ATH_DEFER_ALL_RX =     0x00000001,
  CU_SOFTMAC_ATH_DEFER_ALL_TXDONE = 0x00000002,

  /*
   * Optionally allow packets that fail the 802.11 CRC error check
   * through. Some MAC implementations may not want to worry about
   * packet corruption and explicitly do NOT want to get packets
   * with CRC errors, others may want them.
   */
  CU_SOFTMAC_ATH_ALLOW_CRCERR = 0x00000004,

  /*
   * CU_SOFTMAC_ATH_RAW_MODE permits unencapsulated access to the
   * entire "802.11" frame, i.e. the normal extra 5 byte header
   * will not be prepended, and the burden is on the MAC layer to
   * ensure that the Atheros hardware doesn't make any unwanted modifications
   * to outgoing packets.
   * XXX not yet implemented
   */
  CU_SOFTMAC_ATH_RAW_MODE = 0x00000008,
};

/*
 * ath_cu_softmac_set_phocus_state directs the state of
 * the "phocus" antenna if attached.
 */
void cu_softmac_ath_set_phocus_state(u_int16_t state,int16_t settle);

#endif
