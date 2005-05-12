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


/**
 * @file softmac_netif.c
 * @brief SoftMAC functions for creating a network interface
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include "../cu_softmac_api.h"
#include "softmac_netif.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");

typedef struct CU_SOFTMAC_NETIF_INSTANCE_t {
  struct list_head list;
  CU_SOFTMAC_NETIF_TX_FUNC txfunc;
  void* txfunc_priv;
  struct net_device* dev;
} CU_SOFTMAC_NETIF_INSTANCE;

/**
 * @brief Keep a reference to the head of our linked list of instances.
 */
static LIST_HEAD(softmac_netif_instance_list);

static int cu_softmac_netif_hard_start_xmit(struct sk_buff* skb,
					    struct net_device* dev);
/*
 * This function creates an ethernet interface
 */
CU_SOFTMAC_NETIF_HANDLE
cu_softmac_netif_create_eth(char* name,
			    char* macaddr,
			    CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc) {
}

/*
 * Destroy a previously created ethernet interface
 */
void
cu_softmac_netif_destroy(CU_SOFTMAC_NETIF_HANDLE nif) {
}

/*
 * A client should call this function when it has a packet ready
 * to send up to higher layers of the network stack.
 */
int
cu_softmac_rx_packet(CU_SOFTMAC_NETIF_HANDLE nif,struct sk_buff* packet) {
}

/*
 * Set the function to call when a packet is ready for transmit
 */
int
cu_softmac_set_tx_callback(CU_SOFTMAC_NETIF_HANDLE nif,
			   CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc) {
}

/*
 * Function handed over as the "hard_start" element in the network
 * device structure.
 */
static int cu_softmac_netif_hard_start_xmit(struct sk_buff* skb,
					    struct net_device* dev) {
  CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
}

static int __init softmac_netif_init(void)
{
  printk(KERN_ALERT "Loading SoftMAC netif module\n");
  return 0;
}

static void __exit softmac_netif_exit(void)
{
  printk(KERN_ALERT "Unloading SoftMAC netif module\n");
}

module_init(softmac_netif_init);
module_exit(softmac_netif_exit);
