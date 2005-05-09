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
** CheesyMAC Exported Functions
**
**
 */


/*
 * Basic properties of a cheesymac instance
 */
typedef struct {
  int32_t txbitrate;
  int32_t defertx;
  int32_t defertxdone;
  int32_t deferrx;
  int32_t maxinflight;
} CU_SOFTMAC_CHEESYMAC_PARAMETERS;

/*
 * Create a CheesyMAC instance.
 * This will fill *macinfo in with the appropriate cheesymac instance
 * information.
 */
int
cu_softmac_cheesymac_create_instance(CU_SOFTMAC_MACLAYER_INFO* macinfo,
				     CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/*
 * Destroy a cheesymac instance
 */
int
cu_softmac_cheesymac_destroy_instance(void* macpriv);

/*
 * Get MAC layer info for CheesyMAC
 */
int
cu_softmac_cheesymac_get_macinfo(void* macpriv,
				 CU_SOFTMAC_MACLAYER_INFO* macinfo);

/*
 * Get the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_get_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/*
 * Set the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_set_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/*
 * Get the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_get_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

/*
 * Set the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_set_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);
