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

#ifndef SOFTMAC_REMOTEMAC_H
#define SOFTMAC_REMOTEMAC_H

/* remote tx commands and flags */
enum {
    CU_SOFTMAC_REMOTE_TX_NOOP = 0,
    CU_SOFTMAC_REMOTE_TX_LONGHDR = 1,
    CU_SOFTMAC_REMOTE_TX_SHORTHDR = 2,
    CU_SOFTMAC_REMOTE_TX_ETH = 3,
    CU_SOFTMAC_REMOTE_TX_DELAY_SEND_RESET = 4,
    CU_SOFTMAC_REMOTE_TX_DELAY_SEND = 5,
    CU_SOFTMAC_REMOTE_TX_RATE = 6,
};

/* remote rx flags */
enum {
    CU_SOFTMAC_REMOTE_RX_NOOP = 64,
    CU_SOFTMAC_REMOTE_RX_RSSI = 65,
    CU_SOFTMAC_REMOTE_RX_CHANNEL = 66,
    CU_SOFTMAC_REMOTE_RX_RATE = 67,
    CU_SOFTMAC_REMOTE_RX_TIME = 68,
    CU_SOFTMAC_REMOTE_RX_CRCERR = 69,
};

#endif
