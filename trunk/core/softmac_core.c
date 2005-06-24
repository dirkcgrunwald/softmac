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
 * @file softmac_core.c
 * @brief SoftMAC Core Services
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
MODULE_AUTHOR("Jeff Fifield");

/*
** 
** List handling
**
*/

#define NAME_HASH_BITS 8
static struct hlist_head layer_name_head[1<<NAME_HASH_BITS];
static struct hlist_head mac_name_head[1<<NAME_HASH_BITS];
static struct hlist_head phy_name_head[1<<NAME_HASH_BITS];

// XXX should be locking the list for changes
//lock_t softmac_hlist_lock;

static inline struct hlist_head *softmac_layer_hash(const char *name)
{
    unsigned hash = full_name_hash(name, strnlen(name, CU_SOFTMAC_NAME_SIZE));
    return &layer_name_head[hash & ((1 << NAME_HASH_BITS)-1)];
}

static inline struct hlist_head *softmac_macinfo_hash(const char *name)
{
    unsigned hash = full_name_hash(name, strnlen(name, CU_SOFTMAC_NAME_SIZE));
    return &mac_name_head[hash & ((1 << NAME_HASH_BITS)-1)];
}

static inline struct hlist_head *softmac_phyinfo_hash(const char *name)
{
    unsigned hash = full_name_hash(name, strnlen(name, CU_SOFTMAC_NAME_SIZE));
    return &phy_name_head[hash & ((1 << NAME_HASH_BITS)-1)];
}

static void
softmac_lists_init(void)
{
    int i;
    
    for (i=0; i<ARRAY_SIZE(layer_name_head); i++)
	INIT_HLIST_HEAD(&layer_name_head[i]);
    
    for (i=0; i<ARRAY_SIZE(mac_name_head); i++)
	INIT_HLIST_HEAD(&mac_name_head[i]);
    
    for (i=0; i<ARRAY_SIZE(phy_name_head); i++)
	INIT_HLIST_HEAD(&phy_name_head[i]);
}

/*
** 
** Implementations of our "do nothing" functions to avoid null checks
**
*/

int
cu_softmac_phy_attach_mac_dummy(CU_SOFTMAC_PHY_HANDLE nfh,struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo) 
{
  return -1;
}

void
cu_softmac_phy_detach_mac_dummy(CU_SOFTMAC_PHY_HANDLE nfh,void* mypriv) 
{
}

u_int64_t
cu_softmac_phy_get_time_dummy(CU_SOFTMAC_PHY_HANDLE nfh) 
{
    return 0;
}

void
cu_softmac_phy_set_time_dummy(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t time) 
{
}

void
cu_softmac_phy_schedule_work_asap_dummy(CU_SOFTMAC_PHY_HANDLE nfh) 
{
}

struct sk_buff*
cu_softmac_phy_alloc_skb_dummy(CU_SOFTMAC_PHY_HANDLE nfh,int datalen) 
{
  return 0;
}

void
cu_softmac_phy_free_skb_dummy(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb)
{
    /*
     * Free the packet if it's not null -- not technically "nothing" but
     * may prevent some memory leakage in corner cases.
     */
    if (skb) {
	dev_kfree_skb_any(skb);
    }
}

int
cu_softmac_phy_sendpacket_dummy(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) 
{
    /*
     * Free the packet if it's not null -- not technically "nothing" but
     * may prevent some memory leakage in corner cases.
     */
    if (skb) {
	dev_kfree_skb_any(skb);
    }
    return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

int
cu_softmac_phy_sendpacket_keepskbonfail_dummy(CU_SOFTMAC_PHY_HANDLE nfh,int max_packets_inflight,struct sk_buff* skb) 
{
    /*
     * Free the packet if it's not null -- not technically "nothing" but
     * may prevent some memory leakage in corner cases.
     */
    if (skb) {
	dev_kfree_skb_any(skb);
    }
    return CU_SOFTMAC_PHY_SENDPACKET_OK;
}

u_int32_t
cu_softmac_phy_get_duration_dummy(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb) 
{ 
    return 0; 
}


u_int32_t
cu_softmac_phy_get_txlatency_dummy(CU_SOFTMAC_PHY_HANDLE nfh) 
{
    return 0;
}

static int
cu_softmac_mac_detach_dummy(CU_SOFTMAC_PHY_HANDLE nfh,void* mydata,int intop)
{
    return 0;
}

static int
cu_softmac_mac_work_dummy(CU_SOFTMAC_PHY_HANDLE nfh,
			      void* mydata, int intop)
{
    return 0;
}

static int
cu_softmac_mac_packet_rx_dummy(CU_SOFTMAC_PHY_HANDLE nfh,
			       void* mydata,
			       struct sk_buff* packet,
			       int intop)
{
    return 0;
}

static int
cu_softmac_mac_packet_tx_done_dummy(CU_SOFTMAC_PHY_HANDLE nfh,
				    void* mydata,
				    struct sk_buff* packet,
				    int intop)
{
    return 0;
}

static int
cu_softmac_mac_packet_tx_dummy(void* mydata,struct sk_buff* packet,
				   int intop)
{
    return 0;
}

static int
cu_softmac_mac_attach_to_phy_dummy(void* handle,
				       CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
    return 0;
}

static int
cu_softmac_mac_detach_from_phy_dummy(void* handle)
{
    return 0;
}

static int 
cu_softmac_mac_set_rx_func_dummy(void* handle,
				     CU_SOFTMAC_MAC_RX_FUNC rxfunc,
				     void* rxpriv)
{
    return 0;
}

static int
cu_softmac_mac_set_unload_notify_func_dummy(void* handle,
						CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,
						void* unloadpriv)
{
    return 0;
}


/*
** 
** SoftMAC Core API
**
*/

/* returns CU_SOFTMAC_MACLAYER_INFO or CU_SOFTMAC_PHYLAYER_INFO cast to void* */
void *
cu_softmac_layer_new_instance(const char *name)
{
    printk("%s\n", __func__);

    struct hlist_head *head;
    struct hlist_node *p;

    head = softmac_layer_hash(name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_LAYER_INFO *l = hlist_entry(p, CU_SOFTMAC_LAYER_INFO, name_hlist);
	if (!strncmp(l->name, name, CU_SOFTMAC_NAME_SIZE))
	    return (l->cu_softmac_layer_new_instance)(l->layer_private);
    }
    return 0;
}

void
cu_softmac_layer_free_instance(const char *name, void *inst)
{
    printk("%s\n", __func__);

    struct hlist_head *head;
    struct hlist_node *p;

    head = softmac_layer_hash(name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_LAYER_INFO *l = hlist_entry(p, CU_SOFTMAC_LAYER_INFO, name_hlist);
	if (!strncmp(l->name, name, CU_SOFTMAC_NAME_SIZE)) {
	    l->cu_softmac_layer_free_instance(l->layer_private, inst);
	    return;
	}
    }
}


void 
cu_softmac_layer_register(CU_SOFTMAC_LAYER_INFO *info, const char *name)
{
    struct hlist_head *head;
    struct hlist_node *p;

    /* check for existing */
    head = softmac_layer_hash(name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_LAYER_INFO *l = hlist_entry(p, CU_SOFTMAC_LAYER_INFO, name_hlist);
	if (!strncmp(l->name, name, CU_SOFTMAC_NAME_SIZE)) {
	    printk("%s warning: layer %s already registered\n", __func__, name);
	    return;
	}
    }
    
    /* add it to the list */
    hlist_add_head(&info->name_hlist, head);
    printk("%s registered layer %s\n", __func__, name);
}

void 
cu_softmac_layer_unregister(CU_SOFTMAC_LAYER_INFO *info)
{
    struct hlist_head *head;
    struct hlist_node *p;

    head = softmac_layer_hash(info->name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_LAYER_INFO *l = hlist_entry(p, CU_SOFTMAC_LAYER_INFO, name_hlist);
	if (l == info) {
	    printk("%s unregistered layer %s\n", __func__, info->name);
	    hlist_del(&l->name_hlist);
	    return;
	}
    }
}

CU_SOFTMAC_PHYLAYER_INFO *
cu_softmac_phyinfo_alloc(void)
{
    printk("%s\n", __func__);

    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;

    phyinfo = kmalloc(sizeof(CU_SOFTMAC_PHYLAYER_INFO) ,GFP_ATOMIC);
    if (phyinfo) {
	cu_softmac_phyinfo_init(phyinfo);
	atomic_set (&phyinfo->refcnt, 1);
    }
    return phyinfo;
}

void
cu_softmac_phyinfo_free(CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    printk("%s\n", __func__);

    if (atomic_dec_and_test(&phyinfo->refcnt)) {
	printk("%s freed\n", __func__);
	kfree(phyinfo);
    }
}

void
cu_softmac_phyinfo_init(CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
    printk("%s\n", __func__);

    memset(phyinfo, 0, sizeof(CU_SOFTMAC_PHYLAYER_INFO));
    phyinfo->cu_softmac_attach_mac = cu_softmac_phy_attach_mac_dummy;
    phyinfo->cu_softmac_detach_mac = cu_softmac_phy_detach_mac_dummy;
    phyinfo->cu_softmac_get_time = cu_softmac_phy_get_time_dummy;
    phyinfo->cu_softmac_set_time = cu_softmac_phy_set_time_dummy;
    phyinfo->cu_softmac_schedule_work_asap = cu_softmac_phy_schedule_work_asap_dummy;
    phyinfo->cu_softmac_alloc_skb = cu_softmac_phy_alloc_skb_dummy;
    phyinfo->cu_softmac_free_skb = cu_softmac_phy_free_skb_dummy;
    phyinfo->cu_softmac_sendpacket = cu_softmac_phy_sendpacket_dummy;
    phyinfo->cu_softmac_sendpacket_keepskbonfail = cu_softmac_phy_sendpacket_keepskbonfail_dummy;
    phyinfo->cu_softmac_get_duration = cu_softmac_phy_get_duration_dummy;
    phyinfo->cu_softmac_get_txlatency = cu_softmac_phy_get_txlatency_dummy;
    phyinfo->phyhandle = 0;
}

void 
cu_softmac_phyinfo_register(CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
    struct hlist_head *head;
    struct hlist_node *p;

    /* check for existing */
    head = softmac_phyinfo_hash(phyinfo->name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_PHYLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_PHYLAYER_INFO, name_hlist);
	if (!strncmp(m->name, phyinfo->name, CU_SOFTMAC_NAME_SIZE)) {
	    printk("%s warning: phy %s already registered\n", __func__, m->name);
	    return;
	}
    }
    
    /* add it to the list */
    hlist_add_head(&phyinfo->name_hlist, head);
    printk("%s registered %s\n", __func__, phyinfo->name);
}

void 
cu_softmac_phyinfo_unregister(CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
    struct hlist_head *head;
    struct hlist_node *p;

    head = softmac_phyinfo_hash(phyinfo->name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_PHYLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_PHYLAYER_INFO, name_hlist);
	if (m == phyinfo) {
	    hlist_del(&m->name_hlist);
	    printk("%s unregistered %s\n", __func__, phyinfo->name);
	    return;
	}
    }
    
    /* XXX detatch ? */
}

CU_SOFTMAC_PHYLAYER_INFO *
cu_softmac_phyinfo_get_by_name(const char *name)
{
    printk("%s\n", __func__);

    struct hlist_head *head;
    struct hlist_node *p;
    CU_SOFTMAC_PHYLAYER_INFO *ret = 0;

    head = softmac_phyinfo_hash(name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_PHYLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_PHYLAYER_INFO, name_hlist);
	if (!strncmp(m->name, name, CU_SOFTMAC_NAME_SIZE))
	    ret = m;
    }

    if (ret)
	atomic_inc(&ret->refcnt);

    return ret;
}

CU_SOFTMAC_MACLAYER_INFO *
cu_softmac_macinfo_alloc(void)
{
    printk("%s\n", __func__);

    CU_SOFTMAC_MACLAYER_INFO *macinfo;

    macinfo = kmalloc(sizeof(CU_SOFTMAC_MACLAYER_INFO),GFP_ATOMIC);
    if (macinfo) {
	cu_softmac_macinfo_init(macinfo);
	atomic_set(&macinfo->refcnt, 1);
    }
    return macinfo;
}

void
cu_softmac_macinfo_free(CU_SOFTMAC_MACLAYER_INFO *macinfo)
{
    printk("%s\n", __func__);

    if (atomic_dec_and_test(&macinfo->refcnt)) {
	printk("%s freed\n", __func__);
	kfree(macinfo);
    }
}

void
cu_softmac_macinfo_init(CU_SOFTMAC_MACLAYER_INFO* macinfo)
{
    printk("%s\n", __func__);

    memset(macinfo, 0, sizeof(CU_SOFTMAC_MACLAYER_INFO));
    macinfo->cu_softmac_mac_packet_tx = cu_softmac_mac_packet_tx_dummy;
    macinfo->cu_softmac_mac_packet_tx_done = cu_softmac_mac_packet_tx_done_dummy;
    macinfo->cu_softmac_mac_packet_rx = cu_softmac_mac_packet_rx_dummy;
    macinfo->cu_softmac_mac_work = cu_softmac_mac_work_dummy;
    macinfo->cu_softmac_mac_detach = cu_softmac_mac_detach_dummy;
    macinfo->cu_softmac_mac_attach_to_phy = cu_softmac_mac_attach_to_phy_dummy;
    macinfo->cu_softmac_mac_detach_from_phy = cu_softmac_mac_detach_from_phy_dummy;
    macinfo->cu_softmac_mac_set_rx_func = cu_softmac_mac_set_rx_func_dummy;
    macinfo->cu_softmac_mac_set_unload_notify_func = cu_softmac_mac_set_unload_notify_func_dummy;
    macinfo->mac_private = 0;
}

void 
cu_softmac_macinfo_register(CU_SOFTMAC_MACLAYER_INFO* macinfo)
{
    printk("%s\n", __func__);

    struct hlist_head *head;
    struct hlist_node *p;

    /* check for existing */
    head = softmac_macinfo_hash(macinfo->name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_MACLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_MACLAYER_INFO, name_hlist);
	if (!strncmp(m->name, macinfo->name, CU_SOFTMAC_NAME_SIZE)) {
	    printk("%s warning: mac %s already registered\n", __func__, m->name);
	    return;
	}
    }
    
    /* add it to the list */
    hlist_add_head(&macinfo->name_hlist, head);
    printk("%s registered %s\n", __func__, macinfo->name);
}

void 
cu_softmac_macinfo_unregister(CU_SOFTMAC_MACLAYER_INFO* macinfo)
{
    struct hlist_head *head;
    struct hlist_node *p;

    head = softmac_macinfo_hash(macinfo->name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_MACLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_MACLAYER_INFO, name_hlist);
	if (m == macinfo) {
	    printk("%s unregistered %s\n", __func__, macinfo->name);
	    hlist_del(&m->name_hlist);
	    return;
	}
    }
    
    /* XXX detatch ? */
}

CU_SOFTMAC_MACLAYER_INFO *
cu_softmac_macinfo_get_by_name(const char *name)
{
    printk("%s\n", __func__);

    struct hlist_head *head;
    struct hlist_node *p;
    CU_SOFTMAC_MACLAYER_INFO *ret = 0;

    head = softmac_macinfo_hash(name);
    hlist_for_each(p, head) {
	CU_SOFTMAC_MACLAYER_INFO *m = hlist_entry(p, CU_SOFTMAC_MACLAYER_INFO, name_hlist);
	if (!strncmp(m->name, name, CU_SOFTMAC_NAME_SIZE))
	    ret = m;
    }

    if (ret)
	atomic_inc(&ret->refcnt);

    return ret;
}


static int __init softmac_core_init(void)
{
    printk("%s\n", __func__);

    softmac_lists_init();

    return 0;
}

static void __exit softmac_core_exit(void)
{
    printk("%s\n", __func__);
}

module_init(softmac_core_init);
module_exit(softmac_core_exit);

EXPORT_SYMBOL(cu_softmac_layer_register);
EXPORT_SYMBOL(cu_softmac_layer_unregister);
EXPORT_SYMBOL(cu_softmac_layer_new_instance);
EXPORT_SYMBOL(cu_softmac_layer_free_instance );

EXPORT_SYMBOL(cu_softmac_phyinfo_register);
EXPORT_SYMBOL(cu_softmac_phyinfo_unregister);
EXPORT_SYMBOL(cu_softmac_phyinfo_get_by_name);
EXPORT_SYMBOL(cu_softmac_phyinfo_alloc);
EXPORT_SYMBOL(cu_softmac_phyinfo_free);
EXPORT_SYMBOL(cu_softmac_phyinfo_init);

EXPORT_SYMBOL(cu_softmac_macinfo_register);
EXPORT_SYMBOL(cu_softmac_macinfo_unregister);
EXPORT_SYMBOL(cu_softmac_macinfo_get_by_name);
EXPORT_SYMBOL(cu_softmac_macinfo_alloc);
EXPORT_SYMBOL(cu_softmac_macinfo_free);
EXPORT_SYMBOL(cu_softmac_macinfo_init);
