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

#ifndef _SOFTMAC_CHEESYMAC_H
#define _SOFTMAC_CHEESYMAC_H

/**
 * @file softmac_cheesymac.h
 * @brief CheesyMAC: an example of an "Alohaesque" wireless MAC constructed
 * using the SoftMAC framework.
 *
 * This particular implementation is intended as a sample/tutorial
 * to demonstrate SoftMAC features. It does not do packet ACKs as required
 * by Aloha. Furthermore, this version uses Atheros-specific PHY layer
 * API calls.
 */

/*
**
**
** CheesyMAC Exported Functions
**
**
 */


/**
 * @brief Basic properties of a CheesyMAC instance.
 */
typedef struct {
  /**
   * @brief 802.11 bitrate to use, specified in units of 512 Kb/s.
   *
   * These units may seem odd, but match what appears in the 802.11
   * PLCP header. Practically speaking this amounts to 2*(bitrate in Mb/s).
   * So, a "2" here means to use the 1 Mb/s rate, 11 the 5.5 Mb/s rate, 22
   * the 11 Mb/s rate.
   */
  int32_t txbitrate;

  /**
   * @brief Do not transmit packets immediately. Queue them and schedule
   * the transmit callback to run as a tasklet.
   */
  int32_t defertx;

  /**
   * @brief Do not delete the sk_buff associated with transmitted packets
   * immediately. Queue them and schedule the "transmit done" callback
   * to run as a tasklet.
   */
  int32_t defertxdone;

  /**
   * @brief Do not handle packet reception immediately. Queue received packets
   * and schedule the "receive" callback to run as a tasklet.
   */
  int32_t deferrx;
  int32_t maxinflight;
} CU_SOFTMAC_CHEESYMAC_PARAMETERS;

/**
 * @brief Create a CheesyMAC instance.
 * This will fill *macinfo in with the appropriate cheesymac instance
 * information.
 */
int
cu_softmac_cheesymac_create_instance(CU_SOFTMAC_MACLAYER_INFO* macinfo,
				     CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/**
 * @brief Destroy a cheesymac instance.
 */
int
cu_softmac_cheesymac_destroy_instance(void* macpriv);

/**
 * @brief Get MAC layer info for CheesyMAC
 */
int
cu_softmac_cheesymac_get_macinfo(void* macpriv,
				 CU_SOFTMAC_MACLAYER_INFO* macinfo);

/**
 * @brief Get the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_get_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/**
 * @brief Set the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_set_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/**
 * @brief Get the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_get_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/**
 * @brief Set the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_set_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);
					 
int 
metamac_set_rx_func_cheesymac(char *name, 
				     void* mydata,
				     CU_SOFTMAC_MAC_RX_FUNC rxfunc,
				     void* rxpriv);
					 
#endif

