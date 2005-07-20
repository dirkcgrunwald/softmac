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
 * This is the NullMAC example module
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include "cu_softmac_api.h"

MODULE_LICENSE("GPL");

/* private instance data */
struct nullmac_instance {
    CU_SOFTMAC_MACLAYER_INFO *macinfo;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;

    CU_SOFTMAC_MAC_RX_FUNC netif_rx;
    void *netif_rx_priv;

    struct tasklet_struct rxq_tasklet;
    struct sk_buff_head   rxq;

    int id;
    rwlock_t lock;
};

static int nullmac_next_id;
static const char *nullmac_name = "nullmac";

/**
 * Every SoftMAC MAC or PHY layer provides a CU_SOFTMAC_LAYER_INFO interface
 */
static CU_SOFTMAC_LAYER_INFO the_nullmac;

/* attach to a phy layer */
static int
nullmac_mac_attach(void *me, CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    struct nullmac_instance *inst = me;
    int ret = -1;
    unsigned long flags;

    write_lock_irqsave(&(inst->lock), flags);
    if (!inst->phyinfo) {
	inst->phyinfo = cu_softmac_phyinfo_get(phyinfo);
	ret = 0;
    }
    write_unlock_irqrestore(&(inst->lock), flags);
    return ret;
}

/* detach from phy layer */
static int
nullmac_mac_detach(void *me)
{
    //printk("%s\n", __func__);
    struct nullmac_instance *inst = me;
    unsigned long flags;

    write_lock_irqsave(&(inst->lock), flags);
    if (inst->phyinfo) {
	cu_softmac_phyinfo_free(inst->phyinfo);
	inst->phyinfo = 0;
    }
    write_unlock_irqrestore(&(inst->lock), flags);
    return 0;
}

static int
nullmac_mac_set_netif_rx_func(void *me, 
				CU_SOFTMAC_MAC_RX_FUNC rxfunc, 
				void *rxpriv) 
{
    //printk("%s\n", __func__);
    struct nullmac_instance *inst = me;
    unsigned long flags;

    write_lock_irqsave(&(inst->lock), flags);

    inst->netif_rx = rxfunc;
    inst->netif_rx_priv = rxpriv;

    write_unlock_irqrestore(&(inst->lock), flags);

    return 0;
}

static int
nullmac_mac_packet_tx(void *me, struct sk_buff *skb, int intop)
{
    //printk("%s\n", __func__);
    struct nullmac_instance *inst = me; 

    BUG_ON(intop);

    read_lock(&(inst->lock));
    if (inst->phyinfo) {
	inst->phyinfo->cu_softmac_phy_sendpacket(inst->phyinfo->phy_private, 1, skb);
    }
    read_unlock(&(inst->lock));

    return CU_SOFTMAC_MAC_NOTIFY_OK;
}

static void
nullmac_rx_tasklet(unsigned long data)
{
    //printk("%s\n", __func__);
    struct nullmac_instance *inst = (struct nullmac_instance *)data;
    struct sk_buff *skb;
    
    read_lock(&(inst->lock));

    while ( (skb = skb_dequeue(&(inst->rxq))) ) {
	if (inst->netif_rx)
	    inst->netif_rx(inst->netif_rx_priv, skb);
	else if (inst->phyinfo)
	    inst->phyinfo->cu_softmac_phy_free_skb(inst->phyinfo->phy_private, skb);
	else
	    kfree_skb(skb);
   }

    read_unlock(&(inst->lock));
}

static int
nullmac_mac_packet_rx(void *me, struct sk_buff *skb, int intop)
{
    //printk("%s\n", __func__);

    struct nullmac_instance *inst = me;

    skb_queue_tail(&(inst->rxq), skb);
    if (intop) {
	tasklet_schedule(&(inst->rxq_tasklet));
    } else {
	nullmac_rx_tasklet((unsigned long)me);
    }
    return CU_SOFTMAC_MAC_NOTIFY_OK;
} 

/* create and return a new nullmac instance */
static void *
nullmac_new_instance (void *layer_priv)
{
    //printk("%s\n", __func__);

    struct nullmac_instance *inst;
    void *ret = 0;

    inst = kmalloc(sizeof(struct nullmac_instance), GFP_ATOMIC);
    if (inst) {
	memset(inst, 0, sizeof(struct nullmac_instance));

	inst->lock = RW_LOCK_UNLOCKED;
	inst->id = nullmac_next_id++;

	/* setup the macinfo structure */
	inst->macinfo = cu_softmac_macinfo_alloc();
	inst->macinfo->mac_private = inst;
	inst->macinfo->layer = &the_nullmac;
	snprintf(inst->macinfo->name, CU_SOFTMAC_NAME_SIZE, "%s%d", the_nullmac.name, inst->id);

	/* override some macinfo functions */
	/* the rest remain pointed at the default "do nothing" functions */
	inst->macinfo->cu_softmac_mac_packet_tx = nullmac_mac_packet_tx;
	inst->macinfo->cu_softmac_mac_packet_rx = nullmac_mac_packet_rx;
	inst->macinfo->cu_softmac_mac_attach = nullmac_mac_attach;
	inst->macinfo->cu_softmac_mac_detach = nullmac_mac_detach;
	inst->macinfo->cu_softmac_mac_set_rx_func = nullmac_mac_set_netif_rx_func;

	/* setup rx tasklet */
	tasklet_init(&(inst->rxq_tasklet), nullmac_rx_tasklet, (unsigned long)inst);
	skb_queue_head_init(&(inst->rxq));
	
	/* register with softmac */
	cu_softmac_macinfo_register(inst->macinfo);

	/* note: an instance shouldn't hold a reference to it's own macinfo because
	 * they are really just public and private parts of the same object.
	 */
	/* we've registered with softmac, decrement the ref count */
	cu_softmac_macinfo_free(inst->macinfo);

	ret = inst->macinfo;
    }
    return ret;
}

/* called by softmac_core when a nullmac CU_SOFTMAC_MACLAYER_INFO
 * instance is deallocated 
 */
static void
nullmac_free_instance (void *layer_priv, void *info)
{
    //printk("%s\n", __func__);
    CU_SOFTMAC_MACLAYER_INFO *macinfo = info;
    struct nullmac_instance *inst = macinfo->mac_private;
    if (inst->phyinfo) {
	cu_softmac_phyinfo_free(inst->phyinfo);
    }
    kfree(inst);
}

static int __init 
softmac_nullmac_init(void)
{
    //printk("%s\n", __func__);
    /* register the nullmac layer with softmac */
    strncpy(the_nullmac.name, nullmac_name, CU_SOFTMAC_NAME_SIZE);
    the_nullmac.cu_softmac_layer_new_instance = nullmac_new_instance;
    the_nullmac.cu_softmac_layer_free_instance = nullmac_free_instance;
    cu_softmac_layer_register(&the_nullmac);

    return 0;
}

static void __exit 
softmac_nullmac_exit(void)
{
    //printk("%s\n", __func__);
    /* tell softmac we're leaving */
    cu_softmac_layer_unregister((CU_SOFTMAC_LAYER_INFO *)&the_nullmac);
}

module_init(softmac_nullmac_init);
module_exit(softmac_nullmac_exit);
