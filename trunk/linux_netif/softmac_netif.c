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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include "../cu_softmac_api.h"
#include "softmac_netif.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");

typedef struct CU_SOFTMAC_NETIF_INSTANCE_t {
  struct list_head list;
  spinlock_t devlock;
  int devopen;
  int devregistered;
  int devregpending;
  CU_SOFTMAC_NETIF_TX_FUNC txfunc;
  void* txfunc_priv;
  struct net_device netdev;
} CU_SOFTMAC_NETIF_INSTANCE;

/**
 * @brief Keep a reference to the head of our linked list of instances.
 */
static LIST_HEAD(softmac_netif_instance_list);
static void netif_work_tasklet(unsigned long data);
static DECLARE_TASKLET(softmac_netif_work_tq,netif_work_tasklet,0);

static void softmac_netif_cleanup_instance(CU_SOFTMAC_NETIF_INSTANCE* inst);
static void softmac_netif_init_instance(CU_SOFTMAC_NETIF_INSTANCE* inst);
static CU_SOFTMAC_NETIF_INSTANCE* netif_create_eth(char* name,
						   unsigned char* macaddr,
						   CU_SOFTMAC_NETIF_TX_FUNC txfunc,
						   void* txfunc_priv,
						   int defer);
/*
 * netif "dev" functions
 */
static int softmac_netif_dev_open(struct net_device *dev);
static int softmac_netif_dev_hard_start_xmit(struct sk_buff* skb,
					     struct net_device* dev);
static int softmac_netif_dev_stop(struct net_device *dev);
static void softmac_netif_dev_tx_timeout(struct net_device *dev);

/*
**
** Module parameters
**
*/

static int softmac_netif_test_on_load = 0;
module_param(softmac_netif_test_on_load, int, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(softmac_netif_test_on_load,"Set to non-zero to have the netif module create a fake network interface on load");


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

static void
netif_work_tasklet(unsigned long data) {
  struct list_head* p = 0;
  CU_SOFTMAC_NETIF_INSTANCE* netif_instance = 0;

  list_for_each(p,&softmac_netif_instance_list) {
    netif_instance = list_entry(p,CU_SOFTMAC_NETIF_INSTANCE,list);
    spin_lock(&(netif_instance->devlock));
    if (netif_instance->devregpending && !netif_instance->devregistered) {
      netif_instance->devregpending = 0;
      spin_unlock(&(netif_instance->devlock));
      register_netdev(&(netif_instance->netdev));
      spin_lock(&(netif_instance->devlock));
      netif_instance->devregistered = 1;
      spin_unlock(&(netif_instance->devlock));
    }
    else {
      spin_unlock(&(netif_instance->devlock));
    }
  }
}

/*
 * This function creates an ethernet interface
 */
static CU_SOFTMAC_NETIF_INSTANCE*
netif_create_eth(char* name,unsigned char* macaddr,
		 CU_SOFTMAC_NETIF_TX_FUNC txfunc,void* txfunc_priv,int defer) {
  CU_SOFTMAC_NETIF_INSTANCE* newinst = 0;
  if (!name || !macaddr) {
    return 0;
  }
  
  newinst = kmalloc(sizeof(CU_SOFTMAC_NETIF_INSTANCE),GFP_ATOMIC);
  if (newinst) {
    struct net_device* dev = &(newinst->netdev);
    softmac_netif_init_instance(newinst);
    list_add_tail(&newinst->list,&softmac_netif_instance_list);

    /*
     * Fire up the instance...
     */
    spin_lock(&(newinst->devlock));
    ether_setup(dev);
    strncpy(dev->name,name,IFNAMSIZ);
    memcpy(dev->dev_addr,macaddr,6);
    dev->priv = newinst;
    dev->open = softmac_netif_dev_open;
    dev->stop = softmac_netif_dev_stop;
    dev->hard_start_xmit = softmac_netif_dev_hard_start_xmit;
    dev->tx_timeout = softmac_netif_dev_tx_timeout;
    dev->watchdog_timeo = 5 * HZ;			/* XXX */
    spin_unlock(&(newinst->devlock));
    if (defer) {
      tasklet_schedule(&softmac_netif_work_tq);
    }
    else {
      register_netdev(&(newinst->netdev));
      spin_lock(&(newinst->devlock));
      newinst->devregistered = 1;
      spin_unlock(&(newinst->devlock));
    }
  }
  return newinst;
}

/*
 * This function creates an ethernet interface
 */
CU_SOFTMAC_NETIF_HANDLE
cu_softmac_netif_create_eth(char* name,
			    unsigned char* macaddr,
			    CU_SOFTMAC_NETIF_TX_FUNC txfunc,
			    void* txfunc_priv) {
  return netif_create_eth(name,macaddr,txfunc,txfunc_priv,in_irq());
}


/*
 * Destroy a previously created network interface
 */
void
cu_softmac_netif_destroy(CU_SOFTMAC_NETIF_HANDLE nif) {
  CU_SOFTMAC_NETIF_INSTANCE* inst = nif;  
  if (inst) {
    list_del(&(inst->list));
    softmac_netif_cleanup_instance(inst);
    kfree(inst);
    inst = 0;
    nif = 0;
  }
}

static void
softmac_netif_cleanup_instance(CU_SOFTMAC_NETIF_INSTANCE* inst) {
  if (inst) {
    // XXX figure out locking...
    spin_lock(&(inst->devlock));
    inst->txfunc = 0;
    inst->txfunc_priv = 0;
    if (inst->devregistered) {
      inst->devregistered = 0;
      unregister_netdevice(&(inst->netdev));
    }
    spin_unlock(&(inst->devlock));
  }
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
  
  if (inst) {
    struct net_device* dev = &(inst->netdev);

    packet->dev = dev;
    packet->mac.raw = packet->data;
    /*
     * XXX this assumes ethernet packets -- make more generic!
     */
    //packet->nh.raw = packet->data + sizeof(struct ether_header);
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
void
cu_softmac_set_tx_callback(CU_SOFTMAC_NETIF_HANDLE nif,
			   CU_SOFTMAC_NETIF_TX_FUNC txfunc,
			   void* txfunc_priv) {
  CU_SOFTMAC_NETIF_INSTANCE* inst = nif;

  if (inst) {
    spin_lock(&(inst->devlock));
    inst->txfunc = txfunc;
    inst->txfunc_priv = txfunc_priv;
    spin_unlock(&(inst->devlock));
  }
}

/*
 * Function handed over as the "hard_start" element in the network
 * device structure.
 */
static int softmac_netif_dev_hard_start_xmit(struct sk_buff* skb,
					     struct net_device* dev) {
  int txresult = 0;
  printk(KERN_DEBUG "SoftMAC netif: hard_start\n");
  if (dev && dev->priv) {
    CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
    if (inst->txfunc) {
      spin_lock(&(inst->devlock));
      txresult = (inst->txfunc)(inst->txfunc_priv,skb);
      spin_unlock(&(inst->devlock));
    }
    else {
      /*
       * Just drop the packet on the floor if there's no callback set
       */
      dev_kfree_skb(skb);
      skb = 0;
      txresult = 0;
    }
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
  int result = 0;
  printk(KERN_DEBUG "SoftMAC netif: dev_open\n");
  if (dev && dev->priv) {
    CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
    /*
     * Mark the device as "open"
     */
    spin_lock(&(inst->devlock));
    if (!inst->devregistered) {
      /*
       *  Someone is opening us -> we've been registered
       */
      inst->devregistered = 1;
    }
    if (!inst->devopen) {
      netif_start_queue(dev);
      inst->devopen = 1;
    }
    spin_unlock(&(inst->devlock));
  }
  return result;
}

static int softmac_netif_dev_stop(struct net_device *dev) {
  int result = 0;
  printk(KERN_DEBUG "SoftMAC netif: dev_stop\n");
  if (dev && dev->priv) {
    CU_SOFTMAC_NETIF_INSTANCE* inst = dev->priv;
    /*
     * Mark the device as "closed"
     * We only acquire the device lock if the device
     * is still marked as "registered". We should
     * only get called as an "unregistered" device
     * if we're in the process of being shut down
     * and have already acquired the spinlock.
     */
    if (inst->devregistered) spin_lock(&(inst->devlock));
    if (inst->devopen) {
      netif_stop_queue(dev);
      inst->devopen = 0;
    }
    if (inst->devregistered) spin_unlock(&(inst->devlock));
  }
  return result;
}

static void softmac_netif_dev_tx_timeout(struct net_device *dev) {
  printk(KERN_DEBUG "SoftMAC netif: dev_tx timeout!\n");
}

static int testtxfunc(void* priv,struct sk_buff* skb) {
  printk(KERN_DEBUG "Got packet for transmit, length %d bytes\n",skb->len);
  return 0;
}
static int __init softmac_netif_init(void)
{
  printk(KERN_ALERT "Loading SoftMAC netif module\n");
  if (softmac_netif_test_on_load) {
    printk(KERN_ALERT "Creating test interface foo0\n");
    netif_create_eth("foo0","\0\1\2\3\4\5",testtxfunc,0,1);
  }
  return 0;
}

static void __exit softmac_netif_exit(void)
{
  printk(KERN_DEBUG "Unloading SoftMAC netif module\n");
  if (!list_empty(&softmac_netif_instance_list)) {
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
      cu_softmac_netif_destroy(netif_instance);
      netif_instance = 0;
    }
  }
  else {
    printk(KERN_DEBUG "SoftMAC netif: No instances found\n");
  }

}

EXPORT_SYMBOL(cu_softmac_netif_create_eth);
EXPORT_SYMBOL(cu_softmac_netif_destroy);
EXPORT_SYMBOL(cu_softmac_netif_rx_packet);
EXPORT_SYMBOL(cu_softmac_set_tx_callback);

module_init(softmac_netif_init);
module_exit(softmac_netif_exit);
