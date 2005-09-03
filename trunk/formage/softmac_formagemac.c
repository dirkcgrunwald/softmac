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
 * This is the rsmac example module
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

static int formagemac_next_id;
static const char *formagemac_name = "formagemac";

//
// This is used as the magic identifier for a "formage" packet
//
static const int deadbeef = 0xdeadbeef;

/**
 * Every SoftMAC MAC or PHY layer provides a CU_SOFTMAC_LAYER_INFO interface
 */
static CU_SOFTMAC_LAYER_INFO the_formagemac;

struct formagemac_inst_proc_data {
    struct list_head list;
    struct formagemac_instance *inst;
    int id;
    char name[CU_SOFTMAC_NAME_SIZE];
    struct proc_dir_entry *parent;
};

enum {
    FORMAGEMAC_INST_PROC_RESET_COUNTS,
    FORMAGEMAC_INST_PROC_FORMAGE_ENABLE,
    FORMAGEMAC_INST_PROC_RX_COUNT,
    FORMAGEMAC_INST_PROC_RX_DROP_COUNT,
    FORMAGEMAC_INST_PROC_FIXED_ERROR_COUNT,
    FORMAGEMAC_INST_PROC_FAKE_ERROR_RATE,
};

struct formagemac_inst_proc_entry {
    const char *name;
    mode_t mode;
    int id;
};

static const struct formagemac_inst_proc_entry formagemac_inst_proc_entries[] = {
    {
	"reset_counts",
	0200,
	FORMAGEMAC_INST_PROC_RESET_COUNTS
    },
    {
	"rx_count",
	0444,
	FORMAGEMAC_INST_PROC_RX_COUNT
    },
    {
	"formage_enable",
	0644,
	FORMAGEMAC_INST_PROC_FORMAGE_ENABLE
    },
    {
	"rx_drop_count",
	0444,
	FORMAGEMAC_INST_PROC_RX_DROP_COUNT
    },
    {
	"fixed_error_count",
	0444,
	FORMAGEMAC_INST_PROC_FIXED_ERROR_COUNT
    },
    {
	"fake_error_rate",
	0644,
	FORMAGEMAC_INST_PROC_FAKE_ERROR_RATE
    },
    /* terminator, don't remove */
    {
	0,
	0,
	-1
    },
};

/* private instance data */
struct formagemac_instance {
    CU_SOFTMAC_MACLAYER_INFO *macinfo;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;

    CU_SOFTMAC_MAC_RX_FUNC netif_rx;
    void *netif_rx_priv;

    struct tasklet_struct rxq_tasklet;
    struct sk_buff_head   rxq;

    int fake_error_rate;
    int fixed_error_count;
    int rx_drop_count;
    int rx_count;
    int formage_enable;

    int id;
    struct proc_dir_entry *procfs_dir;
    struct list_head procfs_data;
    rwlock_t lock;
};

//
// Yes, this is a bogus CRC. We'll fix later
//
int boguscrc(char *p, int l)
{
  int a = 0;
  int i;
  for (i = 0; i < l; i++) {
    a += p[i];
  }
  return a;
}


static int
formagemac_inst_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data) 
{
    int result = 0;
    struct formagemac_inst_proc_data* procdata = data;
    if (procdata && procdata->inst) {
	struct formagemac_instance* inst = procdata->inst;
	char* dest = (page + off);
	
	switch (procdata->id) {
	case FORMAGEMAC_INST_PROC_RX_COUNT:
	    result = snprintf(dest, count, "%d\n", inst->rx_count);
	    break;
	case FORMAGEMAC_INST_PROC_RX_DROP_COUNT:
	    result = snprintf(dest, count, "%d\n", inst->rx_drop_count);
	    break;
	case FORMAGEMAC_INST_PROC_FIXED_ERROR_COUNT:
	    result = snprintf(dest, count, "%d\n", inst->fixed_error_count);
	    break;
	case FORMAGEMAC_INST_PROC_FAKE_ERROR_RATE:
	    result = snprintf(dest, count, "%d\n", inst->fake_error_rate);
	    break;
	case FORMAGEMAC_INST_PROC_FORMAGE_ENABLE:
	    result = snprintf(dest, count, "%d\n", inst->formage_enable);
	    break;
	default:
	    result = 0;
	    *eof = 1;
	    break;
	}
    }
    return result;
}

static int
formagemac_inst_write_proc(struct file *file, const char __user *buffer, 
		       unsigned long count, void *data)
{
    int result = 0;
    struct formagemac_inst_proc_data* procdata = data;
    unsigned long flags;

    if (procdata && procdata->inst) {
	struct formagemac_instance* inst = procdata->inst;
	static const int maxkdatalen = 256;
	char kdata[maxkdatalen];
	char* endp = 0;
	long intval = 0;
	
	/*
	 * Drag the data over into kernel land
	 */
	if (maxkdatalen <= count) {
	    copy_from_user(kdata,buffer,(maxkdatalen-1));
	    kdata[maxkdatalen-1] = 0;
	    result = (maxkdatalen-1);
	}
	else {
	    copy_from_user(kdata,buffer,count);
	    result = count;
	}
	
	switch (procdata->id) {
	case FORMAGEMAC_INST_PROC_RESET_COUNTS:
	    intval = simple_strtol(kdata, &endp, 10);
	    write_lock_irqsave(&(inst->lock), flags);
	    inst->rx_count = 0;
	    inst->rx_drop_count = 0;
	    inst->fixed_error_count = 0;
	    write_unlock_irqrestore(&(inst->lock), flags);
	    break;
	case FORMAGEMAC_INST_PROC_FAKE_ERROR_RATE:
	    intval = simple_strtol(kdata, &endp, 10);
	    write_lock_irqsave(&(inst->lock), flags);
	    inst->fake_error_rate = intval;
	    write_unlock_irqrestore(&(inst->lock), flags);
	    break;
	case FORMAGEMAC_INST_PROC_FORMAGE_ENABLE:
	    intval = simple_strtol(kdata, &endp, 10);
	    write_lock_irqsave(&(inst->lock), flags);
	    inst->formage_enable = (intval == 0) ? 0 : 1;
	    write_unlock_irqrestore(&(inst->lock), flags);
	    break;
	default:
	    break;
	}
    }
    else {
	result = count;
    }
    
    return result;
}

static int
formagemac_make_procfs_entries(struct formagemac_instance *inst)
{
    int i, result = 0;
    struct proc_dir_entry *ent;
    struct formagemac_inst_proc_data *proc_data;

    if (inst) {
	inst->procfs_dir = inst->macinfo->proc;
	
	for (i=0; (formagemac_inst_proc_entries[i].name && formagemac_inst_proc_entries[i].name[0]); i++) {
	    ent = create_proc_entry(formagemac_inst_proc_entries[i].name,
				    formagemac_inst_proc_entries[i].mode,
				    inst->procfs_dir);
	    ent->owner = THIS_MODULE;
	    ent->read_proc = formagemac_inst_read_proc;
	    ent->write_proc = formagemac_inst_write_proc;
	    ent->data = kmalloc(sizeof(struct formagemac_inst_proc_data), GFP_ATOMIC);

	    proc_data = ent->data;
	    INIT_LIST_HEAD(&(proc_data->list));
	    list_add_tail(&(proc_data->list), &(inst->procfs_data));
	    proc_data->inst = inst;
	    proc_data->id = formagemac_inst_proc_entries[i].id;
	    strncpy(proc_data->name, formagemac_inst_proc_entries[i].name, CU_SOFTMAC_NAME_SIZE);
	    proc_data->parent = inst->procfs_dir;
	}
    }
    return result;
}

static int
formagemac_delete_procfs_entries(struct formagemac_instance *inst)
{
    int result = 0;
    if (inst) {
	struct list_head* tmp = 0;
	struct list_head* p = 0;
	struct formagemac_inst_proc_data* proc_entry_data = 0;
	
	/*
	 * Remove individual entries and delete their data
	 */
	list_for_each_safe(p, tmp, &(inst->procfs_data)) {
	    proc_entry_data = list_entry(p, struct formagemac_inst_proc_data, list);
	    list_del(p);
	    remove_proc_entry(proc_entry_data->name, proc_entry_data->parent);
	    kfree(proc_entry_data);
	    proc_entry_data = 0;
	}
	
    }
    return result;
}

/* attach to a phy layer */
static int
formagemac_mac_attach(void *me, CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    //printk("%s\n", __func__);
    struct formagemac_instance *inst = me;
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
formagemac_mac_detach(void *me)
{
    //printk("%s\n", __func__);
    struct formagemac_instance *inst = me;
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
formagemac_mac_set_netif_rx_func(void *me, 
			    CU_SOFTMAC_MAC_RX_FUNC rxfunc, 
			    void *rxpriv) 
{
    //printk("%s\n", __func__);
    struct formagemac_instance *inst = me;
    unsigned long flags;

    write_lock_irqsave(&(inst->lock), flags);

    inst->netif_rx = rxfunc;
    inst->netif_rx_priv = rxpriv;

    write_unlock_irqrestore(&(inst->lock), flags);

    return 0;
}

static int
formagemac_mac_packet_tx(void *me, struct sk_buff *skb, int intop)
{
    //printk("%s\n", __func__);
    struct formagemac_instance *inst = me; 

    BUG_ON(intop);

    read_lock(&(inst->lock));
    if (inst->phyinfo) {

      //
      // Compute CRC of original message
      //
      int crc = boguscrc(skb->data, skb->len);
      //
      // Put in header
      // 
      skb_cow(skb, sizeof(deadbeef));
      char *label = skb_push(skb, sizeof(deadbeef));
      *((int *)label) = deadbeef;
      //
      // Put in CRC
      //
      skb = skb_padto(skb, skb -> len + sizeof(crc));
      char *crcptr = skb_put(skb, sizeof(crc));
      *((int*) crcptr) = crc;

      inst->phyinfo->cu_softmac_phy_sendpacket(inst->phyinfo->phy_private, 1, skb);
    }
    else { 
	kfree_skb(skb);
    }
    read_unlock(&(inst->lock));

    return CU_SOFTMAC_MAC_NOTIFY_OK;
}

static void
formagemac_rx_tasklet(unsigned long data)
{
    //printk("%s\n", __func__);
    struct formagemac_instance *inst = (struct formagemac_instance *)data;
    struct sk_buff *skb;
    
    read_lock(&(inst->lock));

    while ( (skb = skb_dequeue(&(inst->rxq))) ) {
	inst->rx_count++;
	if (inst->netif_rx) {
	  inst->netif_rx(inst->netif_rx_priv, skb);
	  continue;
	} 
	// drop
	inst->rx_drop_count++;
	if (inst->phyinfo) {
	  inst->phyinfo->cu_softmac_phy_free_skb(inst->phyinfo->phy_private, skb);
	} else {
	  kfree_skb(skb);
	}
    }

    read_unlock(&(inst->lock));
}

static int
formagemac_mac_packet_rx(void *me, struct sk_buff *skb, int intop)
{
    //printk("%s\n", __func__);

    struct formagemac_instance *inst = me;

    char *src = skb->data;
    if ( skb -> len > 4 && ( *((int *) src) == deadbeef )) {
      //
      // Looks valid. Trim the header
      //
      skb_pull(skb, sizeof(deadbeef));
      //
      // Compute the checksum of the payload using our (admittedly cheesy) crc
      //
      int crc = boguscrc(skb->data, skb->len-4);
      char *crcptr = skb -> data + skb->len-4;
      int msgcrc = *(int *)crcptr;
      //
      // Now, remove the CRC
      //
      skb_trim(skb, skb->len-4);
      if (crc == msgcrc) {
	skb_queue_tail(&(inst->rxq), skb);
	if (intop) {
	  tasklet_schedule(&(inst->rxq_tasklet));
	} else {
	  formagemac_rx_tasklet((unsigned long)me);
	}
      } else {
	//
	// It's our packet, but the checksum failed
	//
	return 1;
      }
      return 0;
    } else {
      //
      // Tell multimac it is not our packet
      //
      return -1;
    }
} 



/* create and return a new formagemac instance */
static void *
formagemac_new_instance (void *layer_priv)
{
    //printk("%s\n", __func__);

    struct formagemac_instance *inst;
    void *ret = 0;

    inst = kmalloc(sizeof(struct formagemac_instance), GFP_ATOMIC);
    if (inst) {
	memset(inst, 0, sizeof(struct formagemac_instance));

	inst->lock = RW_LOCK_UNLOCKED;
	inst->id = formagemac_next_id++;
	inst->formage_enable = 1;

	/* setup the macinfo structure */
	inst->macinfo = cu_softmac_macinfo_alloc();
	inst->macinfo->mac_private = inst;
	inst->macinfo->layer = &the_formagemac;
	snprintf(inst->macinfo->name, CU_SOFTMAC_NAME_SIZE, "%s%d", the_formagemac.name, inst->id);

	/* override some macinfo functions */
	/* the rest remain pointed at the default "do nothing" functions */
	inst->macinfo->cu_softmac_mac_packet_tx = formagemac_mac_packet_tx;
	inst->macinfo->cu_softmac_mac_packet_rx = formagemac_mac_packet_rx;
	inst->macinfo->cu_softmac_mac_attach = formagemac_mac_attach;
	inst->macinfo->cu_softmac_mac_detach = formagemac_mac_detach;
	inst->macinfo->cu_softmac_mac_set_rx_func = formagemac_mac_set_netif_rx_func;

	/* setup rx tasklet */
	tasklet_init(&(inst->rxq_tasklet), formagemac_rx_tasklet, (unsigned long)inst);
	skb_queue_head_init(&(inst->rxq));
	
	/* register with softmac */
	cu_softmac_macinfo_register(inst->macinfo);
	
	/* setup procfs */
	inst->procfs_dir = (struct proc_dir_entry *)inst->macinfo->proc;
	INIT_LIST_HEAD(&inst->procfs_data);
	formagemac_make_procfs_entries(inst);

	/* we've registered with softmac, decrement the ref count */
	cu_softmac_macinfo_free(inst->macinfo);

	ret = inst->macinfo;
    }
    return ret;
}

/* called by softmac_core when a formagemac CU_SOFTMAC_MACLAYER_INFO
 * instance is deallocated 
 */
static void
formagemac_free_instance (void *layer_priv, void *info)
{
    //printk("%s\n", __func__);
    CU_SOFTMAC_MACLAYER_INFO *macinfo = info;
    struct formagemac_instance *inst = macinfo->mac_private;
    if (inst->phyinfo) {
	cu_softmac_phyinfo_free(inst->phyinfo);
    }
    formagemac_delete_procfs_entries(inst);
    kfree(inst);
}

static int __init 
softmac_formagemac_init(void)
{
    //printk("%s\n", __func__);
    /* register the formagemac layer with softmac */
    strncpy(the_formagemac.name, formagemac_name, CU_SOFTMAC_NAME_SIZE);
    the_formagemac.cu_softmac_layer_new_instance = formagemac_new_instance;
    the_formagemac.cu_softmac_layer_free_instance = formagemac_free_instance;
    cu_softmac_layer_register(&the_formagemac);

    return 0;
}

static void __exit 
softmac_formagemac_exit(void)
{
    //printk("%s\n", __func__);
    /* tell softmac we're leaving */
    cu_softmac_layer_unregister((CU_SOFTMAC_LAYER_INFO *)&the_formagemac);
}

module_init(softmac_formagemac_init);
module_exit(softmac_formagemac_exit);
