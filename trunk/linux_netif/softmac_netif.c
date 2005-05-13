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
  spinlock_t devlock;
  int devopen;
  CU_SOFTMAC_NETIF_TX_FUNC txfunc;
  void* txfunc_priv;
  struct net_device netdev;
} CU_SOFTMAC_NETIF_INSTANCE;

/**
 * @brief Keep a reference to the head of our linked list of instances.
 */
static LIST_HEAD(softmac_netif_instance_list);

static void softmac_netif_cleanup_instance(CU_SOFTMAC_NETIF_INSTANCE* inst);
static void softmac_netif_init_instance(CU_SOFTMAC_NETIF_INSTANCE* inst);

/*
 * netif "dev" functions
 */
static int softmac_netif_dev_open(struct net_device *dev);
static int softmac_netif_dev_hard_start_xmit(struct sk_buff* skb,
					     struct net_device* dev);
static int softmac_netif_dev_stop(struct net_device *dev);
static void softmac_netif_dev_tx_timeout(struct net_device *dev);

/*
 * Initialize a netif instance
 */
static void
softmac_netif_init_instance(CU_SOFTMAC_NETIF_INSTANCE* inst) {
  if (inst) {
    memset(inst,0,sizeof(CU_SOFTMAC_NETIF_INSTANCE));
    INIT_LIST_HEAD(&inst->list);
    list_add_tail(&inst->list,&softmac_netif_instance_list);
    inst->devlock = SPIN_LOCK_UNLOCKED;
  }
}

/*
 * This function creates an ethernet interface
 */
CU_SOFTMAC_NETIF_HANDLE
cu_softmac_netif_create_eth(char* name,
			    char* macaddr,
			    CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc,
			    void* txfunc_priv) {
  CU_SOFTMAC_NETIF_HANDLE newinst = 0;
  newinst = kmalloc(sizeof(CU_SOFTMAC_NETIF_INSTANCE),GFP_ATOMIC);
  if (newinst) {
    struct net_device* dev = &(newinst->netdev);
    softmac_netif_init_instance(newinst);
    /*
     * Fire up the instance...
     */
    spin_lock(&(newinst->devlock));
    ether_setup(dev);
    dev->priv = newinst;
    dev->open = softmac_netif_dev_open;
    dev->stop = softmac_netif_dev_stop;
    dev->hard_start_xmit = softmac_netif_dev_hard_start_xmit;
    dev->tx_timeout = softmac_netif_dev_tx_timeout;
    dev->watchdog_timeo = 5 * HZ;			/* XXX */

    register_netdev(&(newinst->netdev));
  }
  return newinst;
}

/*
 * Destroy a previously created network interface
 */
void
cu_softmac_netif_destroy(CU_SOFTMAC_NETIF_HANDLE nif) {
  if (nif) {
  }
}

static void
softmac_netif_cleanup_instance(CU_SOFTMAC_NETIF_INSTANCE* inst) {
}

/*
 * A client should call this function when it has a packet ready
 * to send up to higher layers of the network stack.
 */
int
cu_softmac_netif_rx_packet(CU_SOFTMAC_NETIF_HANDLE nif,
			   struct sk_buff* packet) {
  int result = 0;
  CU_SOFTMAC_NETIF_INSTANCE* inst = nif;  
  
  if (inst && inst->dev) {
    struct net_device* dev = nif->dev;

    packet->dev = dev;
    packet->mac.raw = packet->data;
    /*
     * XXX this assumes ethernet packets -- make more generic!
     */
    packet->nh.raw = packet->data + sizeof(struct ether_header);
    packet->protocol = eth_type_trans(packet,dev);
    spin_lock(&(inst->devlock));
    if (inst->devopen) {
      netif_rx(packet);
    }
    else {
      result = -1;
    }
    spin_unlock(&(inst->devlock));
  }
  else {
    result = -1;
  }

  return result;
}

/*
 * Set the function to call when a packet is ready for transmit
 */
int
cu_softmac_set_tx_callback(CU_SOFTMAC_NETIF_HANDLE nif,
			   CU_SOFTMAC_MAC_NETIF_TX_FUNC txfunc,
			   void* txfunc_priv) {
}

/*
 * Function handed over as the "hard_start" element in the network
 * device structure.
 */
static int softmac_netif_dev_hard_start_xmit(struct sk_buff* skb,
					     struct net_device* dev) {
  int txresult = 0;

  CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
  if (inst && inst->txfunc) {
    spin_lock(&(inst->devlock));
    txresult = (inst->txfunc)(inst->txfunc_priv,skb);
    spin_unlock(&(inst->devlock));
  }
  else {
    /*
     * Returning a "1" from here indicates transmit failure.
     */
    txresult = 1;
  }

  return txresult;
}

static int softmac_netif_dev_open(struct net_device *dev) {
  CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
  if (inst) {
    /*
     * Mark the device as "open"
     */
    spin_lock(&(inst->devlock));
    inst->devopen = 1;
    spin_unlock(&(inst->devlock));
  }
}

static int softmac_netif_dev_stop(struct net_device *dev) {
  CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
  if (inst) {
    /*
     * Mark the device as "closed"
     */
    spin_lock(&(inst->devlock));
    netif_stop_queue(dev);
    inst->devopen = 0;
    spin_unlock(&(inst->devlock));
  }
}

static void softmac_netif_dev_tx_timeout(struct net_device *dev) {
  printk(KERN_DEBUG "SoftMAC netif: dev_tx timeout!\n");
}


static int __init softmac_netif_init(void)
{
  printk(KERN_ALERT "Loading SoftMAC netif module\n");
  return 0;
}

static void __exit softmac_netif_exit(void)
{
  printk(KERN_ALERT "Unloading SoftMAC netif module\n");
  if (!list_empty(&cheesymac_instance_list)) {
    printk(KERN_DEBUG "SoftMAC netif: Deleting instances\n");
    CU_SOFTMAC_NETIF_INSTANCE* netif_instance = 0;
    struct list_head* tmp = 0;
    struct list_head* p = 0;
    
    /*
     * Walk through all instances, remove from the linked 
     * list and then dispose of them cleanly.
     */
    list_for_each_safe(p,tmp,&softmac_netif_instance_list) {
      netif_instance = list_entry(p,CU_SOFTMAC_NETIF_INSTANCE,list);
      printk(KERN_DEBUG "SoftMAC netif: Detaching and destroying instance %p\n",netif_instance);
      list_del(p);
      softmac_netif_cleanup_instance(netif_instance);
      kfree(netif_instance);
    }
  }
  else {
    printk(KERN_DEBUG "CheesyMAC: No instances found\n");
  }

}

module_init(softmac_netif_init);
module_exit(softmac_netif_exit);
