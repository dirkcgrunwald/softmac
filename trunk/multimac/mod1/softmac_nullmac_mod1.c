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
typedef struct {
    CU_SOFTMAC_MACLAYER_INFO *macinfo;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;

    CU_SOFTMAC_MAC_RX_FUNC myrxfunc;
    void *myrxfunc_priv;

    int id;
} NULLMAC_INSTANCE;

static int nullmac_next_id;

/**
 * Every SoftMAC MAC or PHY layer provides a CU_SOFTMAC_LAYER_INFO interface
 */
static CU_SOFTMAC_LAYER_INFO the_nullmac;

/* attach to a phy layer */
static int
nullmac_mac_attach(void *me, CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    NULLMAC_INSTANCE *inst = me;
    if (!inst->phyinfo) {
	inst->phyinfo = cu_softmac_phyinfo_get(phyinfo);
	return 0;
    }
    /* error: already attached */
    return -1;
}

/* detach from phy layer */
static int
nullmac_mac_detach(void *me)
{
    NULLMAC_INSTANCE *inst = me;

    if (inst->phyinfo) {
	cu_softmac_phyinfo_free(inst->phyinfo);
	inst->phyinfo = 0;
    }
    return 0;
}

static int
nullmac_mac_set_rx_func(void *me, CU_SOFTMAC_MAC_RX_FUNC rxfunc, void* rxpriv)
{
    printk("%p %s\n", me, __func__);
    NULLMAC_INSTANCE *inst = me;
    if (inst && rxfunc) {
	inst->myrxfunc = rxfunc;
	inst->myrxfunc_priv = rxpriv;
    } else {
	printk("%s error\n", __func__);
    }
}

static int my_rxhelper(void* mydata, struct sk_buff* packet, int intop)  
{
    NULLMAC_INSTANCE *inst = mydata;
    printk("rx func %p %s\n", mydata, the_nullmac.name);
    if (inst && inst->myrxfunc)
	(inst->myrxfunc)(inst->myrxfunc_priv, packet);
    else
	printk("%s error\n", __func__);
}			 
			 
static int my_txhelper(void* mydata, struct sk_buff* packet, int intop) {
	printk("tx func %s\n", the_nullmac.name);
	multimac_tx(mydata, packet, 0);
}


/* create and return a new nullmac instance */
static void *
nullmac_new_instance (void *layer_priv)
{
    printk("%s\n", __func__);

    NULLMAC_INSTANCE *inst;
    void *ret = 0;

    inst = kmalloc(sizeof(NULLMAC_INSTANCE), GFP_ATOMIC);
    if (inst) {
	memset(inst, 0, sizeof(NULLMAC_INSTANCE));

	inst->id = nullmac_next_id++;

	/* setup the macinfo structure */
	inst->macinfo = cu_softmac_macinfo_alloc();
	inst->macinfo->mac_private = inst;
	inst->macinfo->layer = &the_nullmac;
	inst->macinfo->cu_softmac_mac_packet_rx = my_rxhelper;
	inst->macinfo->cu_softmac_mac_packet_tx = my_txhelper;
	inst->macinfo->cu_softmac_mac_set_rx_func = nullmac_mac_set_rx_func;

	snprintf(inst->macinfo->name, CU_SOFTMAC_NAME_SIZE, "%s%d", the_nullmac.name, inst->id);

	/* override some macinfo functions */
	/* the rest remain pointed at the default "do nothing" functions */
	inst->macinfo->cu_softmac_mac_attach = nullmac_mac_attach;
	inst->macinfo->cu_softmac_mac_detach = nullmac_mac_detach;

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
    printk("%s\n", __func__);

    CU_SOFTMAC_MACLAYER_INFO *macinfo = info;
    NULLMAC_INSTANCE *inst = macinfo->mac_private;
    if (inst->phyinfo) {
	cu_softmac_phyinfo_free(inst->phyinfo);
    }
    kfree(inst);
}

static int __init 
softmac_nullmac_init(void)
{
    printk("%s\n", __func__);

    /* register the nullmac layer with softmac */
    strncpy(the_nullmac.name, "mac1", CU_SOFTMAC_NAME_SIZE);
    the_nullmac.cu_softmac_layer_new_instance = nullmac_new_instance;
    the_nullmac.cu_softmac_layer_free_instance = nullmac_free_instance;
    cu_softmac_layer_register(&the_nullmac);

    return 0;
}

static void __exit 
softmac_nullmac_exit(void)
{
    printk("%s\n", __func__);

    /* tell softmac we're leaving */
    cu_softmac_layer_unregister((CU_SOFTMAC_LAYER_INFO *)&the_nullmac);
}

module_init(softmac_nullmac_init);
module_exit(softmac_nullmac_exit);
