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

#ifndef _SOFTMAC_NETIF_H
#define _SOFTMAC_NETIF_H

/**
 * @file softmac_netif.h
 * @brief SoftMAC functions for creating a network interface 
 */

typedef void* CU_SOFTMAC_NETIF_HANDLE;
typedef int (*CU_SOFTMAC_MAC_NETIF_TX_FUNC)(void*,struct sk_buff* packet);

/*
 * This function creates an ethernet interface
 */
CU_SOFTMAC_NETIF_HANDLE
cu_softmac_netif_create_eth(char* name,
			    char* macaddr,
			    CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc,
			    void* txfunc_priv);

/*
 * Destroy a previously created ethernet interface
 */
void
cu_softmac_netif_destroy(CU_SOFTMAC_NETIF_HANDLE nif);

/*
 * A client should call this function when it has a packet ready
 * to send up to higher layers of the network stack.
 * XXX this assumes ethernet-encapsulated packets -- should
 * make things more general at some point.
 */
int
cu_softmac_netif_rx_packet(CU_SOFTMAC_NETIF_HANDLE nif,struct sk_buff* packet);

/*
 * Set the function to call when a packet is ready for transmit
 */
int
cu_softmac_set_tx_callback(CU_SOFTMAC_NETIF_HANDLE nif,
			   CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc,
			   void* txfunc_priv);

#endif
