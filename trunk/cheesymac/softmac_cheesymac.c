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
 * @file softmac_cheesymac.c
 * @brief CheesyMAC: an example of an "Alohaesque" wireless MAC constructed
 * using the SoftMAC framework.
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
#include "cu_softmac_ath_api.h"
#include "softmac_netif.h"
#include "softmac_cheesymac.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");


/*
**
** Per-instance data for the MAC
**
*/


/**
 * @brief Some global constants
 */
enum {
  /**
   * @brief Maximum length of a proc filesystem entry
   */
  CHEESYMAC_PROCDIRNAME_LEN = 64,
};

/**
 * @brief This is the structure containing all of the state information
 * required for each CheesyMAC instance.
 */
typedef struct CHEESYMAC_INSTANCE_t {
  /**
   * @brief Use a Linux kernel linked list to keep track of all instances
   */
  struct list_head list;

  /**
   * @brief Lock access to MAC when altering basic parameters.
   */
  spinlock_t mac_busy;

  /**
   * @brief Keep a handle to the currently attached PHY layer.
   * XXX turn this into a read/write spinlock?
   */
  CU_SOFTMAC_PHYLAYER_INFO myphy;

  /**
   * @brief Track whether or not the MAC layer is currently attached
   * to a PHY layer.
   */
  int attached_to_phy;

  /**
   * @brief Keep a pointer to the "packet receive" function
   */
  CU_SOFTMAC_MAC_RX_FUNC myrxfunc;
  void* myrxfunc_priv;
  CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC myunloadnotifyfunc;
  void* myunloadnotifyfunc_priv; 


  /**
   * @brief We keep a unique ID for each instance we create in order to
   * do things like create separate proc directories for the settings
   * on each one.
   */
  int instanceid;

  /**
   * @brief Keep a handle to the root procfs directory for this instance
   */
  struct proc_dir_entry* my_procfs_root;

  /**
   * @brief The name of our proc filesystem directory
   */
  char procdirname[CHEESYMAC_PROCDIRNAME_LEN];

  /**
   * @brief The proc directory entry structure corresponding to our
   * proc filesystem directory.
   */
  struct proc_dir_entry* my_procfs_dir;

  /**
   * @brief Track all of the proc filesystem entries allocated for
   * this CheesyMAC instance.
   */
  struct list_head my_procfs_data;

  /*
   * Some parameters determining basic phy properties,
   * behavior w.r.t. top half/bottom half processing
   */

  /**
   * @brief Transmit bitrate encoding to use.
   */
  unsigned char txbitrate;
  int defertx;
  int defertxdone;
  int deferrx;
  int maxinflight;

  /*
   * The cheesymac uses Linux sk_buff queues when it needs
   * to keep packets around for deferred handling.
   */

  /**
   * @brief A Linux kernel sk_buff packet queue containing packets
   * whose transmission has been deferred.
   */
  struct sk_buff_head tx_skbqueue;
  struct sk_buff_head txdone_skbqueue;
  struct sk_buff_head rx_skbqueue;
} CHEESYMAC_INSTANCE;

/*
 * Information about each proc filesystem entry for instance
 * parameters. An array of these will be used to specify
 * the proc entries to create for each MAC instance.
 */
typedef struct {
  const char* name;
  mode_t mode;
  int entryid;
} CHEESYMAC_INST_PROC_ENTRY;

/*
 * Constants for proc entries for each CheesyMAC instance
 */
enum {
  CHEESYMAC_INST_PROC_TXBITRATE,
  CHEESYMAC_INST_PROC_DEFERTX,
  CHEESYMAC_INST_PROC_DEFERTXDONE,
  CHEESYMAC_INST_PROC_DEFERRX,
  CHEESYMAC_INST_PROC_MAXINFLIGHT,
  CHEESYMAC_INST_PROC_COUNT
};

/*
 * Proc filesystem entries for each cheesymac instance. The "data"
 * field will be passed in to a generic read/write routine that
 * will use it to determine how to handle the read/write.
 */
static const CHEESYMAC_INST_PROC_ENTRY cheesymac_inst_proc_entries[] = {
  {
    "txbitrate",
    0644,
    CHEESYMAC_INST_PROC_TXBITRATE
  },  
  {
    "defertx",
    0644,
    CHEESYMAC_INST_PROC_DEFERTX
  },
  {
    "defertxdone",
    0644,
    CHEESYMAC_INST_PROC_DEFERTXDONE
  },
  {
    "deferrx",
    0644,
    CHEESYMAC_INST_PROC_DEFERRX
  },
  {
    "maxinflight",
    0644,
    CHEESYMAC_INST_PROC_MAXINFLIGHT
  },
  /*
   * Using this as the "null terminator" for the item list
   */
  {
    0,
    0,
    -1
  },
};

/**
 * @brief An instance of this data structure is created for each proc
 * filesystem entry and placed into a linked list associated
 * with each instance. This allows us to handle proc filesystem
 * read/write requests.
 */
typedef struct {
  struct list_head list;
  CHEESYMAC_INSTANCE* inst;
  int entryid;
  char name[CHEESYMAC_PROCDIRNAME_LEN];
  struct proc_dir_entry* parentdir;  
} CHEESYMAC_INST_PROC_DATA;

/*
**
** Declarations of functions exported via the MAC info table.
** ("public" members of the MAC base class)
**
*/

/**
 * @brief Notify the MAC layer that it is being removed from the PHY.
 * Exported via pointer as "cu_softmac_detach" to the SoftMAC PHY,
 * of type CU_SOFTMAC_PHY_DETACH_MAC_FUNC
 */
static int
cu_softmac_mac_detach_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,void* mydata,int intop);

/**
 * @brief Notify the MAC layer that it is time to do some work. Exported
 * via pointer as "cu_softmac_work" to the SoftMAC PHY.
 */
static int
cu_softmac_mac_work_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
			      void* mydata, int intop);

/*
 * Notify the MAC layer that a packet has been received -- exported
 * via pointer as "cu_softmac_packet_rx" to the SoftMAC PHY
 */
static int
cu_softmac_mac_packet_rx_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
			       void* mydata,
			       struct sk_buff* packet,
			       int intop);

/**
 * @brief Notify the MAC layer that a packet transmit has completed.
 * Exported via pointer as "cu_softmac_packet_tx_done" to the SoftMAC PHY.
 */
static int
cu_softmac_mac_packet_tx_done_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
				    void* mydata,
				    struct sk_buff* packet,
				    int intop);

/** 
 * @brief Notify the MAC layer that an ethernet-encapsulated packet
 * has been received from up the protocol stack. Exported
 * via pointer as "cu_softmac_packet_tx".
 */
static int
cu_softmac_mac_packet_tx_cheesymac(void* mydata,struct sk_buff* packet,
				   int intop);

/**
 * @brief Tell the MAC layer to attach to the specified PHY layer.
 */
static int
cu_softmac_mac_attach_to_phy_cheesymac(void* handle,
				       CU_SOFTMAC_PHYLAYER_INFO* phyinfo);

/**
 * @brief Tell the MAC layer to detach from the specified PHY layer.
 */
static int
cu_softmac_mac_detach_from_phy_cheesymac(void* handle);

static int 
cu_softmac_mac_set_rx_func_cheesymac(void* handle,
				     CU_SOFTMAC_MAC_RX_FUNC rxfunc,
				     void* rxpriv);

static int
cu_softmac_mac_set_unload_notify_func_cheesymac(void* handle,
						CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,
						void* unloadpriv);

/*
**
** Declarations of internal functions ("private" members)
**
*/

/**
 * @brief Do cleanup when shutting down a CheesyMAC instance --
 * internal utility
 */
static int cheesymac_cleanup_instance(CHEESYMAC_INSTANCE* inst);


/*
 * @brief Do initialization when creating a CheesyMAC instance --
 * internal utility
 */
static int
cheesymac_setup_instance(CHEESYMAC_INSTANCE* inst,
			 CU_SOFTMAC_MACLAYER_INFO* macinfo,
			 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params);

static int cheesymac_make_procfs_entries(CHEESYMAC_INSTANCE* inst);
static int cheesymac_delete_procfs_entries(CHEESYMAC_INSTANCE* inst);
static int cheesymac_inst_read_proc(char *page, char **start, off_t off,
				    int count, int *eof, void *data);
static int cheesymac_inst_write_proc(struct file *file,
				     const char __user *buffer,
				     unsigned long count, void *data);
/*
**
** Module parameters
**
*/

/**
 * @brief Initial values for global MAC default parameter values.
 * Can override these upon module load.
 */
enum {
  CHEESYMAC_DEFAULT_DEFERTX = 0,
  CHEESYMAC_DEFAULT_DEFERTXDONE = 0,
  CHEESYMAC_DEFAULT_DEFERRX = 0,
  CHEESYMAC_DEFAULT_MAXINFLIGHT = 256,
  CHEESYMAC_DEFAULT_DEFERALLRX = 0,
  CHEESYMAC_DEFAULT_DEFERALLTXDONE = 0,
  CHEESYMAC_DEFAULT_TXBITRATE = 2,
};

/**
 * @brief Keep a reference to the head of our linked list of instances.
 */
static LIST_HEAD(cheesymac_instance_list);


/**
 * @brief Some operations, e.g. getting/setting the next instance ID
 * and accessing parameters, should be performed "atomically."
 */
static spinlock_t cheesymac_global_lock = SPIN_LOCK_UNLOCKED;

/**
 * @brief First instance ID to use is 1
 */

static int cheesymac_next_instanceid = 1;

/**
 * @brief Bitrate encoding to use when transmitting packets.
 */
static int cheesymac_txbitrate = CHEESYMAC_DEFAULT_TXBITRATE;

/**
 * @brief Whether or not to defer handling of packet transmission.
 */
static int cheesymac_defertx = CHEESYMAC_DEFAULT_DEFERTX;
static int cheesymac_defertxdone = CHEESYMAC_DEFAULT_DEFERTXDONE;
static int cheesymac_deferrx = CHEESYMAC_DEFAULT_DEFERRX;
static int cheesymac_maxinflight = CHEESYMAC_DEFAULT_MAXINFLIGHT;

#if 0
/*
 * XXX
 * use the ath-specific "deferallrx" and "deferalltxdone"?
 */
static int cheesymac_ath_deferallrx = CHEESYMAC_DEFAULT_DEFERALLRX;
static int cheesymac_ath_deferalltxdone = CHEESYMAC_DEFAULT_DEFERALLTXDONE;
#endif

/*
 * Optionally attach the cheesymac to a softmac phy upon loading
 */
static int cheesymac_attach_on_load = 0;

/*
 * Default root directory for cheesymac procfs entries
 */
static char *cheesymac_procfsroot = "cheesymac";
static struct proc_dir_entry* cheesymac_procfsroot_handle = 0;

/*
 * Default network interface to use as a softmac phy layer
 */
static char* cheesymac_defaultphy = "ath0";

/*
 * Default network prefix to use for the OS-exported network interface
 * attached to the MAC layer. The unique cheesyMAC ID is used
 * to fill out the "%d" field
 */
static char* cheesymac_netiftemplate = "cheesy%d";

module_param(cheesymac_defertx, int, 0644);
MODULE_PARM_DESC(cheesymac_defertx, "Queue packets and defer transmit to tasklet");
module_param(cheesymac_defertxdone, int, 0644);
MODULE_PARM_DESC(cheesymac_defertxdone, "Queue packets that are finished transmitting and defer handling to tasklet");
module_param(cheesymac_deferrx, int, 0644);
MODULE_PARM_DESC(cheesymac_deferrx, "Queue received packets and defer handling to tasklet");
module_param(cheesymac_maxinflight, int, 0644);
MODULE_PARM_DESC(cheesymac_maxinflight, "Limit the number of packets allowed to be in the pipeline for transmission");

module_param(cheesymac_txbitrate, int, 0644);
MODULE_PARM_DESC(cheesymac_txbitrate, "Default bitrate to use when transmitting packets");

module_param(cheesymac_procfsroot, charp, 0444);
MODULE_PARM_DESC(cheesymac_procfsroot, "Subdirectory in procfs to use for cheesymac parameters/statistics");

module_param(cheesymac_defaultphy, charp, 0644);
MODULE_PARM_DESC(cheesymac_defaultphy, "Network interface to use for SoftMAC PHY layer");

module_param(cheesymac_attach_on_load, int, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(cheesymac_attach_on_load,"Set to non-zero to have the cheesymac attach itself to the softmac upon loading");

static int
cheesymac_netif_txhelper(CU_SOFTMAC_NETIF_HANDLE nif,void* priv,
			 struct sk_buff* packet) {
  CHEESYMAC_INSTANCE* inst = priv;
  if (inst) {
    /*
     * Call the cheesymac tx function. The "intop" indicator
     * is always zero for the particular netif implementation
     * we're using -- in Linux the packet transmission is
     * instigated by a softirq in the bottom half.
     */
    int txresult = cu_softmac_mac_packet_tx_cheesymac(inst,packet,0);
    if (CU_SOFTMAC_MAC_TX_OK != txresult) {
      dev_kfree_skb(packet);
    }
  }
  return 0;
}

static int
cheesymac_netif_unload_helper(CU_SOFTMAC_NETIF_HANDLE netif,void* priv) {
  CHEESYMAC_INSTANCE* inst = priv;
  if (inst) {  
    cu_softmac_mac_set_rx_func_cheesymac(inst,0,0);
  }
  return 0;
}

static int __init softmac_cheesymac_init(void)
{
  printk(KERN_DEBUG "Loading CheesyMAC\n");
  
  cheesymac_procfsroot_handle = proc_mkdir(cheesymac_procfsroot,0);
  cheesymac_procfsroot_handle->owner = THIS_MODULE;
  if (cheesymac_attach_on_load) {
    CU_SOFTMAC_MACLAYER_INFO newmacinfo;
    CU_SOFTMAC_PHYLAYER_INFO athphyinfo;
    struct net_device* mydev = 0;
    printk(KERN_DEBUG "Creating and attaching CheesyMAC to Atheros SoftMAC on %s\n",cheesymac_defaultphy);
    mydev = dev_get_by_name(cheesymac_defaultphy);

    /*
     * Got the device handle, now attempt to get phy info off of it
     */
    if (mydev) {
      cu_softmac_ath_get_phyinfo(mydev,&athphyinfo);
      memset(&newmacinfo,0,sizeof(CU_SOFTMAC_MACLAYER_INFO));

      /*
       * Create an instance of CheesyMAC that we will then attach
       * to the atheros phy layer using the attach function inside
       * of the atheros phy info structure we got earlier.
       */
      if (!cu_softmac_cheesymac_create_instance(&newmacinfo,0)) {
	/*
	 * Now attach our cheesymac instance to the PHY layers
	 */
	printk(KERN_DEBUG "CheesyMAC: Created instance of self, attaching to PHY\n");
	if (!((newmacinfo.cu_softmac_mac_attach_to_phy)(newmacinfo.mac_private,&athphyinfo))) {
	  char ifnamebuf[64];
	  int netid = cheesymac_next_instanceid - 1;
	  CU_SOFTMAC_NETIF_HANDLE newnetif = 0;

	  printk(KERN_DEBUG "CheesyMAC: Attached to PHY\n");
	  /*
	   * Now create our network interface and attach to it
	   */
	  snprintf(ifnamebuf,64,cheesymac_netiftemplate,netid);
	  printk(KERN_DEBUG "CheesyMAC: creating netif %s\n",ifnamebuf);
	  newnetif = cu_softmac_netif_create_eth(ifnamebuf,0,cheesymac_netif_txhelper,newmacinfo.mac_private);
	  printk(KERN_DEBUG "CheesyMAC: Setting mac unload notify func\n");
	  (newmacinfo.cu_softmac_mac_set_unload_notify_func)(newmacinfo.mac_private,cu_softmac_netif_detach,newnetif);
	  printk(KERN_DEBUG "CheesyMAC: Setting netif unload callback func\n");
	  cu_softmac_netif_set_unload_callback(newnetif,cheesymac_netif_unload_helper,newmacinfo.mac_private);
	}
	else {
	  printk(KERN_ALERT "CheesyMAC: Unable to attach to PHY!\n");
	  /*
	   * Whack the cheesymac instance we just created
	   */
	  cu_softmac_cheesymac_destroy_instance(newmacinfo.mac_private);
	  memset(&newmacinfo,0,sizeof(CU_SOFTMAC_MACLAYER_INFO));
	}
      }
      else {
	printk(KERN_ALERT "CheesyMAC: Unable to create instance of self!\n");
      }
    }
    else {
      printk(KERN_ALERT "CheesyMAC: Unable to find net interface %s\n",cheesymac_defaultphy);
    }
  }

  return 0;
}

static void __exit softmac_cheesymac_exit(void)
{
  printk(KERN_DEBUG "Unloading CheesyMAC\n");
  /*
   * Tell any/all softmac PHY layers that we're leaving
   */
  if (!list_empty(&cheesymac_instance_list)) {
    printk(KERN_DEBUG "CheesyMAC: Deleting instances\n");
    CHEESYMAC_INSTANCE* cheesy_instance = 0;
    struct list_head* tmp = 0;
    struct list_head* p = 0;
    
    /*
     * Walk through all instances, remove from the linked 
     * list and then dispose of them cleanly.
     */
    list_for_each_safe(p,tmp,&cheesymac_instance_list) {
      cheesy_instance = list_entry(p,CHEESYMAC_INSTANCE,list);
      printk(KERN_DEBUG "CheesyMAC: Detaching and destroying instance ID %d\n",cheesy_instance->instanceid);
      cu_softmac_cheesymac_destroy_instance(cheesy_instance);
    }
  }
  else {
    printk(KERN_DEBUG "CheesyMAC: No instances found\n");
  }

  /*
   * Remove the root procfs directory very last of all...
   */
  if (cheesymac_procfsroot_handle) {
    remove_proc_entry(cheesymac_procfsroot,0);
  }
}

static void cu_softmac_cheesymac_prep_skb(CHEESYMAC_INSTANCE* inst,
					  CU_SOFTMAC_PHY_HANDLE nfh,
					  struct sk_buff* skb) {
  if (inst && skb) {
    /*
     * XXX use of atheros-specific PHY calls!!!
     */
    cu_softmac_ath_set_default_phy_props(nfh,skb);
    cu_softmac_ath_set_tx_bitrate(nfh,skb,inst->txbitrate);    
  }
}

/*
 * cu_softmac_mac_packet_tx_cheesymac
 * Implementation of "cu_softmac_mac_packet_tx"
 */
static int cu_softmac_mac_packet_tx_cheesymac(void* mydata,
					      struct sk_buff* packet,
					      int intop) {
  CHEESYMAC_INSTANCE* inst = mydata;
  CU_SOFTMAC_PHY_HANDLE nfh = 0;
  int status = CU_SOFTMAC_MAC_TX_OK;
  int txresult = CU_SOFTMAC_PHY_SENDPACKET_OK;

  if (inst) {
    if (!spin_trylock(&(inst->mac_busy))) {
      /*
       * Make sure nobody tries to steal the MAC layer
       * out from under us...
       */
      printk(KERN_DEBUG "CheesyMAC: packet_tx -- mac busy!\n");
      return CU_SOFTMAC_MAC_TX_FAIL;
    }
    nfh = inst->myphy.phyhandle;
    /*
     * Check to see if we're in the top half or bottom half, i.e. are
     * we taking an interrupt right now?
     */
    if (intop) {
      /*
       * As a general rule, try to keep the stuff you do in the top
       * half to a minimum. This is during the immediate handling
       * of an interrupt and the place for time-critical tasks to
       * occur.
       */
      if (inst->defertx && packet) {
	/*
	 * Queue the packet in tx_skbqueue, schedule the "work" method
	 * to run.
	 */
	skb_queue_tail(&(inst->tx_skbqueue),packet);
	/*
	 * XXX schedule work task!
	 */
	(inst->myphy.cu_softmac_schedule_work_asap)(nfh);
	status = CU_SOFTMAC_MAC_TX_OK;
      }
      else if (packet) {
	/*
	 * Send the packet now
	 */
	cu_softmac_cheesymac_prep_skb(inst,nfh,packet);
	txresult = (inst->myphy.cu_softmac_sendpacket)(nfh,inst->maxinflight,packet);
	if (CU_SOFTMAC_PHY_SENDPACKET_OK != txresult) {
	  printk(KERN_ALERT "SoftMAC CheesyMAC: top half packet tx failed: %d\n",txresult);
	}

	status = CU_SOFTMAC_MAC_TX_OK;
      }
    }
    else {
      struct sk_buff* skb = 0;
      /*
       * NOT in top half -- process our transmit queue
       */
      if (packet) {
	skb_queue_tail(&(inst->tx_skbqueue),packet);
      }
      /*
       * Walk our transmit queue, shovelling out packets as we go...
       */
      while ((skb = skb_dequeue(&(inst->tx_skbqueue)))) {
	cu_softmac_cheesymac_prep_skb(inst,nfh,packet);
	txresult = (inst->myphy.cu_softmac_sendpacket)(nfh,inst->maxinflight,packet);
	if (CU_SOFTMAC_PHY_SENDPACKET_OK != txresult) {
	  printk(KERN_ALERT "SoftMAC CheesyMAC: tasklet packet tx failed: %d\n",txresult);
	  /*
	   * N.B. we return an "OK" for the transmit because
	   * we're handling the sk_buff freeing down here --
	   * as far as the caller is concerned we were successful.
	   */
	}
      }
    }
    spin_unlock(&(inst->mac_busy));
  }
  else {
    /*
     * Could not get our instance handle -- let the caller know...
     */
    printk(KERN_ALERT "CheesyMAC: packet_tx -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_TX_FAIL;
  }

  return status;
}

static int cu_softmac_mac_packet_tx_done_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
						void* mydata,
						struct sk_buff* packet,
						int intop) {
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;
  CHEESYMAC_INSTANCE* inst = mydata;

  if (inst) {
    if (!spin_trylock(&(inst->mac_busy))) {
      /*
       * If we can't get the lock tell the PHY layer we're busy...
       */
      printk(KERN_ALERT "CheesyMAC: packet_tx_done -- mac busy!\n");
      return CU_SOFTMAC_MAC_NOTIFY_BUSY;
    }
    /*
     * Check to see if we're supposed to defer handling
     */
    if (intop) {
      if (inst->defertxdone && packet) {
	/*
	 * Queue the packet in txdone_skbqueue, schedule the tasklet
	 */
	skb_queue_tail(&(inst->txdone_skbqueue),packet);
	status = CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN;
      }
      else if (packet) {
	/*
	 * Free the packet immediately, do not run again
	 */
	(inst->myphy.cu_softmac_free_skb)(nfh,packet);
	packet = 0;
	status = CU_SOFTMAC_MAC_NOTIFY_OK;
      }
    }
    else {
      struct sk_buff* skb = 0;
      /*
       * In bottom half -- process any deferred packets
       */
      if (packet) {
	skb_queue_tail(&(inst->txdone_skbqueue),packet);
      }
      while ((skb = skb_dequeue(&(inst->txdone_skbqueue)))) {
	(inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,skb);
      }
    }
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_ALERT "CheesyMAC: packet_tx_done -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }

  return status;
}


static int cu_softmac_mac_packet_rx_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
					      void* mydata,
					      struct sk_buff* packet,
					      int intop) {
  CHEESYMAC_INSTANCE* inst = mydata;
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;

  if (inst) {
    if (!spin_trylock(&(inst->mac_busy))) {
      printk(KERN_ALERT "CheesyMAC: packet_rx -- mac busy!\n");
      return CU_SOFTMAC_MAC_NOTIFY_BUSY;
    }
    if (intop) {
      if (inst->deferrx && packet) {
	/*
	 * Queue packet for later processing
	 */
	skb_queue_tail(&(inst->rx_skbqueue),packet);
	status = CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN;
      }
      else if (packet) {
	/*
	 * Just send the packet up the network stack if we've got
	 * an attached rxfunc, otherwise whack the packet.
	 */
	if (inst->myrxfunc) {
	  (inst->myrxfunc)(inst->myrxfunc_priv,packet);
	}
	else {
	  (inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,packet);
	}
      }
    }
    else {
      struct sk_buff* skb = 0;
      /*
       * Not in top half - walk our rx queue and send packets
       * up the stack
       */
      if (packet) {
	skb_queue_tail(&(inst->rx_skbqueue),packet);
      }
      while ((skb = skb_dequeue(&(inst->rx_skbqueue)))) {
	if (inst->myrxfunc) {
	  (inst->myrxfunc)(inst->myrxfunc_priv,packet);
	}
	else {
	  (inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,packet);
	}
      }
    }
  }
  else {
    printk(KERN_ALERT "CheesyMAC: packet_rx -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }

  return status;
}

static int cu_softmac_mac_work_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
					 void* mydata, int intop) {
  CHEESYMAC_INSTANCE* inst = mydata;
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;

  if (inst) {
    int txresult;
    struct sk_buff* skb = 0;
    /*
     * Walk our transmit queue, shovelling out packets as we go...
     */
    while ((skb = skb_dequeue(&(inst->tx_skbqueue)))) {
      cu_softmac_cheesymac_prep_skb(inst,nfh,skb);
      txresult = (inst->myphy.cu_softmac_sendpacket)(nfh,inst->maxinflight,skb);
      if (CU_SOFTMAC_PHY_SENDPACKET_OK != txresult) {
	printk(KERN_ALERT "SoftMAC CheesyMAC: work packet tx failed: %d\n",txresult);
      }
    }
  }
  else {
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }
  
  return status;
}

/*
 * Notification from the PHY layer that we've been detached
 */
static int cu_softmac_mac_detach_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
					   void* mypriv, int intop) {
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;
  if (mypriv) {
    CHEESYMAC_INSTANCE* inst = mypriv;
    printk(KERN_DEBUG "CheesyMAC: mac_detach -- getting lock\n");
    spin_lock(&(inst->mac_busy));
    printk(KERN_DEBUG "CheesyMAC: mac_detach -- got lock\n");
    /*
     * The PHY layer has finished detaching us -- make sure we don't
     * use it any more.
     */
    
    /*
     * First verify that we're actually attached to some phy layer...
     */
    if (!inst->attached_to_phy) {
      printk(KERN_ALERT "SoftMAC CheesyMAC: Received a detach notification while not attached!\n");
      status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
    }
    else {
      inst->attached_to_phy = 0;
      memset(&(inst->myphy),0,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
      printk(KERN_DEBUG "CheesyMAC: mac_detach -- done\n");
    }
    spin_unlock(&(inst->mac_busy));
    printk(KERN_DEBUG "CheesyMAC: mac_detach -- released lock\n");
  }
  else {
    printk(KERN_ALERT "CheesyMAC: mac_detach -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }
  return status;
}

int cu_softmac_cheesymac_destroy_instance(void* mypriv) {
  CHEESYMAC_INSTANCE* inst = mypriv;
  if (inst) {
    /*
     * Detach/delete this cheesymac instance
     */
    list_del(&(inst->list));
    cheesymac_cleanup_instance(inst);

    kfree(inst);
    inst = 0;
  }
  return 0;
}

int
cu_softmac_cheesymac_create_instance(CU_SOFTMAC_MACLAYER_INFO* macinfo,
				     CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  int result = 0;
  CHEESYMAC_INSTANCE* newinst = 0;

  /*
   * Create a new instance, make it part of a kernel linked list
   */
  newinst = kmalloc(sizeof(CHEESYMAC_INSTANCE),GFP_ATOMIC);
  if (newinst) {
    memset(newinst,0,sizeof(CHEESYMAC_INSTANCE));
    INIT_LIST_HEAD(&newinst->list);
    list_add_tail(&newinst->list,&cheesymac_instance_list);
    INIT_LIST_HEAD(&newinst->my_procfs_data);
    /*
     * Fire up the instance...
     */

    cheesymac_setup_instance(newinst,macinfo,params);

  }
  else {
    printk(KERN_ALERT "CheesyMAC create_instance: Unable to allocate memory!\n");
    result = -1;
  }

  return result;
}

int
cu_softmac_cheesymac_get_macinfo(void* macpriv,
				 CU_SOFTMAC_MACLAYER_INFO* macinfo){
  int result = 0;
  macinfo->cu_softmac_mac_packet_tx = cu_softmac_mac_packet_tx_cheesymac;
  macinfo->cu_softmac_mac_packet_tx_done = cu_softmac_mac_packet_tx_done_cheesymac;
  macinfo->cu_softmac_mac_packet_rx = cu_softmac_mac_packet_rx_cheesymac;
  macinfo->cu_softmac_mac_work = cu_softmac_mac_work_cheesymac;
  macinfo->cu_softmac_mac_detach = cu_softmac_mac_detach_cheesymac;
  macinfo->cu_softmac_mac_attach_to_phy = cu_softmac_mac_attach_to_phy_cheesymac;
  macinfo->cu_softmac_mac_detach_from_phy = cu_softmac_mac_detach_from_phy_cheesymac;
  macinfo->cu_softmac_mac_set_rx_func = cu_softmac_mac_set_rx_func_cheesymac;
  macinfo->cu_softmac_mac_set_unload_notify_func = cu_softmac_mac_set_unload_notify_func_cheesymac;
  macinfo->mac_private = macpriv;

  return result;
}

static int
cheesymac_make_procfs_entries(CHEESYMAC_INSTANCE* inst) {
  int result = 0;

  if (inst) {
    int i = 0;
    struct proc_dir_entry* curprocentry = 0;
    CHEESYMAC_INST_PROC_DATA* curprocdata = 0;

    /*
     * First make the directory. For right now, we're just using the unique
     * MAC layer ID that was assigned upon creation as a name.
     */
    snprintf(inst->procdirname,CHEESYMAC_PROCDIRNAME_LEN,"%d",inst->instanceid);
    inst->my_procfs_dir = proc_mkdir(inst->procdirname,inst->my_procfs_root);
    inst->my_procfs_dir->owner = THIS_MODULE;

    /*
     * Make individual entries. Stop when we get either a null string
     * or an empty string for a name.
     */
    i = 0;
    while (cheesymac_inst_proc_entries[i].name && cheesymac_inst_proc_entries[i].name[0]) {
      //printk(KERN_ALERT "CheesyMAC: Creating proc entry %s, number %d\n",cheesymac_inst_proc_entries[i].name,i);
      curprocentry = create_proc_entry(cheesymac_inst_proc_entries[i].name,
				       cheesymac_inst_proc_entries[i].mode,
				       inst->my_procfs_dir);
      curprocentry->owner = THIS_MODULE;

      /*
       * Allocate and fill out a proc data structure, add it
       * to the linked list for the instance.
       */
      curprocdata = kmalloc(sizeof(CHEESYMAC_INST_PROC_DATA),GFP_ATOMIC);
      INIT_LIST_HEAD((&curprocdata->list));
      list_add_tail(&(curprocdata->list),&(inst->my_procfs_data));
      curprocdata->inst = inst;
      curprocdata->entryid = cheesymac_inst_proc_entries[i].entryid;
      strncpy(curprocdata->name,cheesymac_inst_proc_entries[i].name,CHEESYMAC_PROCDIRNAME_LEN);
      curprocdata->parentdir = inst->my_procfs_dir;

      /*
       * Hook up the new proc entry data
       */
      curprocentry->data = curprocdata;

      /*
       * Set read/write functions for the proc entry.
       */
      curprocentry->read_proc = cheesymac_inst_read_proc;
      curprocentry->write_proc = cheesymac_inst_write_proc;

      i++;
    }
  }
  return result;
}

static int cheesymac_delete_procfs_entries(CHEESYMAC_INSTANCE* inst) {
  int result = 0;
  if (inst) {
    struct list_head* tmp = 0;
    struct list_head* p = 0;
    CHEESYMAC_INST_PROC_DATA* proc_entry_data = 0;

    /*
     * First remove individual entries and delete their data
     */
    list_for_each_safe(p,tmp,&inst->my_procfs_data) {
      proc_entry_data = list_entry(p,CHEESYMAC_INST_PROC_DATA,list);
      list_del(p);
      remove_proc_entry(proc_entry_data->name,proc_entry_data->parentdir);
      kfree(proc_entry_data);
      proc_entry_data = 0;
    }

    /*
     * Lastly, remove the directory
     */
    remove_proc_entry(inst->procdirname,inst->my_procfs_root);
  }
  return result;
}

static int cheesymac_setup_instance(CHEESYMAC_INSTANCE* newinst,
				    CU_SOFTMAC_MACLAYER_INFO* macinfo,
				    CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  int result = 0;
  /*
   * Set up a CheesyMAC instance
   */

  /*
   * Set our instance default parameter values
   */
  newinst->mac_busy = SPIN_LOCK_UNLOCKED;

  /*
   * Now acquire the mac_busy lock and start bashing on the instance...
   */
  spin_lock(&(newinst->mac_busy));
  newinst->attached_to_phy = 0;

  /*
   * Access the global cheesymac variables safely
   */
  spin_lock(&cheesymac_global_lock);
  newinst->instanceid = cheesymac_next_instanceid;
  cheesymac_next_instanceid++;
  newinst->txbitrate = cheesymac_txbitrate;
  newinst->defertx = cheesymac_defertx;
  newinst->defertxdone = cheesymac_defertxdone;
  newinst->deferrx = cheesymac_deferrx;
  newinst->maxinflight = cheesymac_maxinflight;
  spin_unlock(&cheesymac_global_lock);

  if (params) {
    newinst->txbitrate = params->txbitrate;
    newinst->defertx = params->defertx;
    newinst->defertxdone = params->defertxdone;
    newinst->deferrx = params->deferrx;
    newinst->maxinflight = params->maxinflight;
  }

  /*
   * Initialize our packet queues
   */
  skb_queue_head_init(&(newinst->tx_skbqueue));
  skb_queue_head_init(&(newinst->txdone_skbqueue));
  skb_queue_head_init(&(newinst->rx_skbqueue));

  /*
   * Load up the function table/private info so that the SoftMAC layer can
   * communicate with us.
   */
  cu_softmac_cheesymac_get_macinfo(newinst,macinfo);

  /*
   * Create procfs entries
   */
  newinst->my_procfs_root = cheesymac_procfsroot_handle;
  cheesymac_make_procfs_entries(newinst);
  spin_unlock(&(newinst->mac_busy));
  return result;
}

static int
cheesymac_inst_read_proc(char *page, char **start, off_t off,
			 int count, int *eof, void *data) {
  int result = 0;
  CHEESYMAC_INST_PROC_DATA* procdata = data;
  if (procdata && procdata->inst) {
    CHEESYMAC_INSTANCE* inst = procdata->inst;
    char* dest = (page + off);
    int intval = 0;

    switch (procdata->entryid) {
    case CHEESYMAC_INST_PROC_TXBITRATE:
      spin_lock(&(inst->mac_busy));
      intval = inst->txbitrate;
      spin_unlock(&(inst->mac_busy));
      result = snprintf(dest,count,"%d\n",intval);
      *eof = 1;
      break;
    case CHEESYMAC_INST_PROC_DEFERTX:
      spin_lock(&(inst->mac_busy));
      intval = inst->defertx;
      spin_unlock(&(inst->mac_busy));
      result = snprintf(dest,count,"%d\n",intval);
      *eof = 1;
      break;
    case CHEESYMAC_INST_PROC_DEFERTXDONE:
      spin_lock(&(inst->mac_busy));
      intval = inst->defertxdone;
      spin_unlock(&(inst->mac_busy));
      result = snprintf(dest,count,"%d\n",intval);
      *eof = 1;
      break;
    case CHEESYMAC_INST_PROC_DEFERRX:
      spin_lock(&(inst->mac_busy));
      intval = inst->deferrx;
      spin_unlock(&(inst->mac_busy));
      result = snprintf(dest,count,"%d\n",intval);
      *eof = 1;
      break;
    case CHEESYMAC_INST_PROC_MAXINFLIGHT:
      spin_lock(&(inst->mac_busy));
      intval = inst->maxinflight;
      spin_unlock(&(inst->mac_busy));
      result = snprintf(dest,count,"%d\n",intval);
      *eof = 1;
      break;

    default:
      /*
       * Unknown entry -- do something benign
       */
      result = 0;
      *eof = 1;
      break;
    }
  }
  return result;
}

static int
cheesymac_inst_write_proc(struct file *file, const char __user *buffer,
			  unsigned long count, void *data) {
  int result = 0;
  CHEESYMAC_INST_PROC_DATA* procdata = data;
  if (procdata && procdata->inst) {
    CHEESYMAC_INSTANCE* inst = procdata->inst;
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

    switch (procdata->entryid) {
    case CHEESYMAC_INST_PROC_TXBITRATE:
      intval = simple_strtol(kdata,&endp,10);
      spin_lock(&(inst->mac_busy));
      inst->txbitrate = intval;
      spin_unlock(&(inst->mac_busy));
      break;
    case CHEESYMAC_INST_PROC_DEFERTX:
      intval = simple_strtol(kdata,&endp,10);
      spin_lock(&(inst->mac_busy));
      inst->defertx = intval;
      spin_unlock(&(inst->mac_busy));
      break;
    case CHEESYMAC_INST_PROC_DEFERTXDONE:
      intval = simple_strtol(kdata,&endp,10);
      spin_lock(&(inst->mac_busy));
      inst->defertxdone = intval;
      spin_unlock(&(inst->mac_busy));
      break;
    case CHEESYMAC_INST_PROC_DEFERRX:
      intval = simple_strtol(kdata,&endp,10);
      spin_lock(&(inst->mac_busy));
      inst->deferrx = intval;
      spin_unlock(&(inst->mac_busy));
      break;
    case CHEESYMAC_INST_PROC_MAXINFLIGHT:
      intval = simple_strtol(kdata,&endp,10);
      spin_lock(&(inst->mac_busy));
      inst->maxinflight = intval;
      spin_unlock(&(inst->mac_busy));
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
cu_softmac_mac_attach_to_phy_cheesymac(void* handle,
				       CU_SOFTMAC_PHYLAYER_INFO* phyinfo) {
  CHEESYMAC_INSTANCE* inst = handle;
  int result = 0;
  if (inst && phyinfo) {
    CU_SOFTMAC_MACLAYER_INFO cheesymacinfo;
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Attaching to PHY -- getting lock\n");
    spin_lock(&(inst->mac_busy));
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Attaching to PHY -- got lock\n");
    if (inst->attached_to_phy) {
      /*
       * Already attached -- bail out
       */
      printk(KERN_ALERT "SoftMAC CheesyMAC: Attempting to attach to a phy layer while still attached to a phy layer!\n");
      result = -1;
    }
    else {
      /*
       * Set the phy info and then attach a cheesymac instance
       */
      inst->attached_to_phy = 1;
      memcpy(&(inst->myphy),phyinfo,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
      cu_softmac_cheesymac_get_macinfo(handle,&cheesymacinfo);
      printk(KERN_DEBUG "SoftMAC CheesyMAC: About to call PHY attach\n");
      (phyinfo->cu_softmac_attach_mac)(phyinfo->phyhandle,&cheesymacinfo);
      printk(KERN_DEBUG "SoftMAC CheesyMAC: Return from PHY attach\n");
    }
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Unlocking MAC\n");
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_ALERT "SoftMAC CheesyMAC: Invalid MAC/PHY data on attach!\n");
    result = -1;
  }
  return result;
}

static int
cu_softmac_mac_detach_from_phy_cheesymac(void* handle) {
  CHEESYMAC_INSTANCE* inst = handle;
  int result = 0;

  if (inst) {
    /*
     * Let the PHY layer know that we're going away -- we'll receive
     * notification from the PHY layer when it's safe to shut down the
     * MAC layer instance. That cleanup will occur in the callback.
     */
    if (!inst->attached_to_phy) {
      printk(KERN_DEBUG "SoftMAC CheesyMAC: Received a detach request while not attached -- NOP\n");
      /*
       * This isn't so much an error as it is a NOP
       */
      result = 0;
    }
    else {
      /*
       * Explicitly force the phy layer to detach us.
       */
      printk(KERN_DEBUG "SoftMAC CheesyMAC: About to call phy detach\n");
      (inst->myphy.cu_softmac_detach_mac)(inst->myphy.phyhandle,inst);
      printk(KERN_DEBUG "SoftMAC CheesyMAC: Returned from phy detach\n");
    }
  }

  return result;
}

static int 
cu_softmac_mac_set_rx_func_cheesymac(void* mydata,
				     CU_SOFTMAC_MAC_RX_FUNC rxfunc,
				     void* rxpriv) {
  int result = 0;
  CHEESYMAC_INSTANCE* inst = mydata;
  if (inst) {
    spin_lock(&(inst->mac_busy));  
    inst->myrxfunc = rxfunc;
    inst->myrxfunc_priv = rxpriv;
    spin_unlock(&(inst->mac_busy));  
  }

  return result;
}

static int
cu_softmac_mac_set_unload_notify_func_cheesymac(void* mydata,
						CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC unloadfunc,
						void* unloadpriv) {
  int result = 0;
  CHEESYMAC_INSTANCE* inst = mydata;
  if (inst) {
    spin_lock(&(inst->mac_busy));  
    inst->myunloadnotifyfunc = unloadfunc;
    inst->myunloadnotifyfunc_priv = unloadpriv;
    spin_unlock(&(inst->mac_busy));  
  }

  return result;
}


static int cheesymac_cleanup_instance(CHEESYMAC_INSTANCE* inst) {
  int result = 0;
  struct sk_buff* skb = 0;

  /*
   * Clean up after a CheesyMAC instance
   */

  /*
   * Notify folks that we're going away...
   */
  cu_softmac_mac_detach_from_phy_cheesymac(inst);
  if (inst->myunloadnotifyfunc) {
    (inst->myunloadnotifyfunc)(inst->myunloadnotifyfunc_priv);
  }

  /*
   * Now lock the instance and shut it down
   */
  spin_lock(&(inst->mac_busy));

  /*
   * remove procfs entries
   */
  cheesymac_delete_procfs_entries(inst);

  /*
   * Drain queues...
   */
  while ((skb = skb_dequeue(&(inst->tx_skbqueue)))) {
    (inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,skb);
  }
  while ((skb = skb_dequeue(&(inst->txdone_skbqueue)))) {
    (inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,skb);
  }
  while ((skb = skb_dequeue(&(inst->rx_skbqueue)))) {
    (inst->myphy.cu_softmac_free_skb)(inst->myphy.phyhandle,skb);
  }


  spin_unlock(&(inst->mac_busy));

  return result;
}

/*
 * Get the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_get_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  if (params) {
    spin_lock(&cheesymac_global_lock);
    params->txbitrate = cheesymac_txbitrate;
    params->defertx = cheesymac_defertx;
    params->defertxdone = cheesymac_defertxdone;
    params->deferrx = cheesymac_deferrx;
    params->maxinflight = cheesymac_maxinflight;
    spin_unlock(&cheesymac_global_lock);
  }
  else {
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Called get_default_params with null parameters!\n");
  }
}

/*
 * Set the default parameters used to initialize new CheesyMAC instances
 */
void
cu_softmac_cheesymac_set_default_params(CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  if (params) {
    spin_lock(&cheesymac_global_lock);
    cheesymac_txbitrate = params->txbitrate;
    cheesymac_defertx = params->defertx;
    cheesymac_defertxdone = params->defertxdone;
    cheesymac_deferrx = params->deferrx;
    cheesymac_maxinflight = params->maxinflight;
    spin_unlock(&cheesymac_global_lock);
  }
  else {
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Called set_default_params with null parameters!\n");
  }
}

/*
 * Get the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_get_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  if (macpriv && params) {
    CHEESYMAC_INSTANCE* inst = macpriv;
    spin_lock(&(inst->mac_busy));
    params->txbitrate = inst->txbitrate;
    params->defertx = inst->defertx;
    params->defertxdone = inst->defertxdone;
    params->deferrx = inst->deferrx;
    params->maxinflight = inst->maxinflight;    
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Called get_instance_params with bad data!\n");
  }
}

/*
 * Set the parameters of a specific CheesyMAC instance
 */
void
cu_softmac_cheesymac_set_instance_params(void* macpriv,
					 CU_SOFTMAC_CHEESYMAC_PARAMETERS* params) {
  if (macpriv && params) {
    CHEESYMAC_INSTANCE* inst = macpriv;
    spin_lock(&(inst->mac_busy));
    inst->txbitrate = params->txbitrate;
    inst->defertx = params->defertx;
    inst->defertxdone = params->defertxdone;
    inst->deferrx = params->deferrx;
    inst->maxinflight = params->maxinflight;
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_DEBUG "SoftMAC CheesyMAC: Called set_instance_params with bad data!\n");
  }
}


module_init(softmac_cheesymac_init);
module_exit(softmac_cheesymac_exit);

EXPORT_SYMBOL(cu_softmac_cheesymac_create_instance);
EXPORT_SYMBOL(cu_softmac_cheesymac_destroy_instance);
EXPORT_SYMBOL(cu_softmac_cheesymac_get_macinfo);
EXPORT_SYMBOL(cu_softmac_cheesymac_get_default_params);
EXPORT_SYMBOL(cu_softmac_cheesymac_set_default_params);
EXPORT_SYMBOL(cu_softmac_cheesymac_get_instance_params);
EXPORT_SYMBOL(cu_softmac_cheesymac_set_instance_params);

#if 0
/*
 * XXX keeping these around as examples...
 */
static short int myshort = 1;
static int myint = 420;
static long int mylong = 9999;
static char *mystring = "blah";

/* 
 * module_param(foo, int, 0000)
 * The first param is the parameters name
 * The second param is it's data type
 * The final argument is the permissions bits, 
 * for exposing parameters in sysfs (if non-zero) at a later stage.
 */

module_param(myshort, short, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(myshort, "A short integer");
module_param(myint, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(myint, "An integer");
module_param(mylong, long, S_IRUSR);
MODULE_PARM_DESC(mylong, "A long integer");
module_param(mystring, charp, 0000);
MODULE_PARM_DESC(mystring, "A character string");
#endif
