/*
 * softmac_cheesymac.c
 * A "null" sample MAC layer for the CU SoftMAC toolkit
 * This just runs a very simple "ethernet over wireless" protocol 
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "cu_softmac_api.h"
#include "cu_softmac_ath_api.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");


/*
 * By default we don't defer, don't throttle packets in flight.
 * Can override these upon module load.
 */
enum {
  CHEESYMAC_DEFAULT_DEFERTX = 0,
  CHEESYMAC_DEFAULT_DEFERTXDONE = 0,
  CHEESYMAC_DEFAULT_DEFERRX = 0,
  CHEESYMAC_DEFAULT_MAXINFLIGHT = 256,
  CHEESYMAC_DEFAULT_DEFERALLRX = 0,
  CHEESYMAC_DEFAULT_DEFERALLTXDONE = 0,
};


typedef struct  CHEESYMAC_INSTANCE_t {
  struct list_head list;
  CU_SOFTMAC_PHYLAYER_INFO myphy;
  atomic_t attached_to_phy;
  spinlock_t mac_busy;
  unsigned char txbitrate;
  /*
   * XXX expose the "defer" properties...
   */
  int defertx;
  int defertxdone;
  int deferrx;
  int maxinflight;

  /*
   * The cheesymac uses Linux sk_buff queues when it needs
   * to keep packets around for deferred handling.
   */
  struct sk_buff_head tx_skbqueue;
  struct sk_buff_head txdone_skbqueue;
  struct sk_buff_head rx_skbqueue;

  /*
   * We keep a unique ID for each instance we create in order to
   * do things like create separate proc directories for the settings
   * on each one.
   */
  int instanceid;

  /*
   * Keep a handle to the root procfs directory for this instance
   */
  struct proc_dir_entry* my_procfs_root;
 
} CHEESYMAC_INSTANCE;

/*
**
** Declarations of functions used internally and/or exported
**
*/

/*
 * Create a cheesymac instance
 */
static int
cu_softmac_cheesymac_create_instance(CU_SOFTMAC_PHYLAYER_INFO* phyinfo,
				     CU_SOFTMAC_MACLAYER_INFO* macinfo);
/*
 * Destroy a cheesymac instance
 */
static int cu_softmac_cheesymac_destroy_instance(void* mypriv);

/*
 * Notify the MAC layer that it is being removed from the PHY -- exported
 * via pointer as "cu_softmac_detach" to the SoftMAC PHY
 */
static int
cu_softmac_mac_detach_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,void* mydata,int intop);

/*
 * Notify the MAC layer that it is time to do some work -- exported
 * via pointer as "cu_softmac_work" to the SoftMAC PHY
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

/*
 * Notify the MAC layer that a packet transmit has completed -- exported
 * via pointer as "cu_softmac_packet_tx_done" to the SoftMAC PHY
 */
static int
cu_softmac_mac_packet_tx_done_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
				    void* mydata,
				    struct sk_buff* packet,
				    int intop);

/*
 * Notify the MAC layer that an ethernet-encapsulated packet
 * has been received from up the protocol stack -- exported
 * via pointer as "cu_softmac_packet_tx" to the SoftMAC PHY
 */
static int
cu_softmac_mac_packet_tx_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
				   void* mydata,
				   struct sk_buff* packet, int intop);

static int
cu_softmac_mac_attach_to_phy_cheesymac(void* handle,
				       CU_SOFTMAC_PHYLAYER_INFO* phyinfo);
static int
cu_softmac_mac_detach_from_phy_cheesymac(void* handle);

/*
 * Do cleanup when shutting down a CheesyMAC instance -- internal utility
 */
static int cheesymac_cleanup_instance(CHEESYMAC_INSTANCE* inst);


/*
 * Do initialization when creating a CheesyMAC instance -- internal utility
 */
static int
cheesymac_setup_instance(CU_SOFTMAC_PHYLAYER_INFO* phyinfo,
			 CHEESYMAC_INSTANCE* inst,
			 CU_SOFTMAC_MACLAYER_INFO* macinfo);

static int
cu_softmac_cheesymac_set_phyinfo(void* mypriv,
				 CU_SOFTMAC_PHYLAYER_INFO* pinfo);

/*
 * Keep a reference to the head of our linked list of instances
 */
static CHEESYMAC_INSTANCE* my_softmac_instances = 0;

/*
 * First instance ID to use is 1
 */
static spinlock_t cheesymac_instanceid_lock = SPIN_LOCK_UNLOCKED;
static int cheesymac_next_instanceid = 1;
/*
 * Default to 1 Mb/s
 */
static int cheesymac_defaultbitrate = 2;

static int cheesymac_defertx = CHEESYMAC_DEFAULT_DEFERTX;
static int cheesymac_defertxdone = CHEESYMAC_DEFAULT_DEFERTXDONE;
static int cheesymac_deferrx = CHEESYMAC_DEFAULT_DEFERRX;
static int cheesymac_maxinflight = CHEESYMAC_DEFAULT_MAXINFLIGHT;
static int cheesymac_deferallrx = CHEESYMAC_DEFAULT_DEFERALLRX;
static int cheesymac_deferalltxdone = CHEESYMAC_DEFAULT_DEFERALLTXDONE;

/*
 * Optionally attach the cheesymac to a softmac phy upon loading
 */
static int cheesymac_attach_on_load = 0;

/*
 * Default root directory for cheesymac procfs entries
 */
static char *cheesymac_procfsroot = "softmac/cheesymac";

/*
 * Default network interface to use as a softmac phy layer
 */
static char* cheesymac_defaultphy = "ath0";

module_param(cheesymac_defertx, int, 0644);
MODULE_PARM_DESC(cheesymac_defertx, "Queue packets and defer transmit to tasklet");
module_param(cheesymac_defertxdone, int, 0644);
MODULE_PARM_DESC(cheesymac_defertxdone, "Queue packets that are finished transmitting and defer handling to tasklet");
module_param(cheesymac_deferrx, int, 0644);
MODULE_PARM_DESC(cheesymac_deferrx, "Queue received packets and defer handling to tasklet");
module_param(cheesymac_maxinflight, int, 0644);
MODULE_PARM_DESC(cheesymac_maxinflight, "Limit the number of packets allowed to be in the pipeline for transmission");

module_param(cheesymac_procfsroot, charp, 0644);
MODULE_PARM_DESC(cheesymac_procfsroot, "Subdirectory in procfs to use for cheesymac parameters/statistics");

module_param(cheesymac_defaultphy, charp, 0644);
MODULE_PARM_DESC(cheesymac_defaultphy, "Network interface to use for SoftMAC PHY layer");

module_param(cheesymac_attach_on_load, int, S_IRUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(cheesymac_attach_on_load,"Set to non-zero to have the cheesymac attach itself to the softmac upon loading");

/*
 * XXX Finish setting default values for module params!
 */

static int __init softmac_cheesymac_init(void)
{
  printk(KERN_EMERG "Loading CheesyMAC\n");
  if (cheesymac_attach_on_load) {
    CU_SOFTMAC_MACLAYER_INFO newmacinfo;
    CU_SOFTMAC_PHYLAYER_INFO athphyinfo;
    struct net_device* mydev = 0;
    printk(KERN_EMERG "Creating and attaching CheesyMAC to Atheros SoftMAC on %s\n",cheesymac_defaultphy);
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
      if (!cu_softmac_cheesymac_create_instance(&athphyinfo,&newmacinfo)) {
	/*
	 * Now attach our cheesymac instance to the PHY layers
	 */
	printk(KERN_EMERG "CheesyMAC: Created instance of self, attaching to PHY\n");
	//(newmacinfo.cu_softmac_mac_attach_to_phy)(newmacinfo.mac_private,&athphyinfo);
	//printk(KERN_EMERG "CheesyMAC: Attached to PHY\n");
      }
      else {
	printk(KERN_EMERG "CheesyMAC: Unable to create instance of self!\n");
      }
    }
    else {
      printk(KERN_EMERG "CheesyMAC: Unable to find net interface %s\n",cheesymac_defaultphy);
    }
    /*
     * XXX do cleanup if "attach on load" fails
     */
  }

  return 0;
}

static void __exit softmac_cheesymac_exit(void)
{
  printk(KERN_EMERG "Unloading CheesyMAC\n");
  /*
   * Tell any/all softmac PHY layers that we're leaving
   */
  if (my_softmac_instances) {
    CHEESYMAC_INSTANCE* cheesy_instance = 0;
    struct list_head* tmp = 0;
    struct list_head* p = 0;
    
    /*
     * Walk through all instances, remove from the linked 
     * list and then dispose of them cleanly.
     */
    list_for_each_safe(p,tmp,&(my_softmac_instances->list)) {
      cheesy_instance = list_entry(p,CHEESYMAC_INSTANCE,list);
      list_del(p);
      cu_softmac_mac_detach_from_phy_cheesymac(cheesy_instance);
      cheesymac_cleanup_instance(cheesy_instance);
      kfree(cheesy_instance);
    }
  }
}

static int cu_softmac_mac_packet_tx_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet, int intop) {
  CHEESYMAC_INSTANCE* inst = mydata;
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;

  if (inst) {
    if (spin_trylock(&(inst->mac_busy))) {
      /*
       *
       */
      printk(KERN_EMERG "CheesyMAC: packet_tx -- mac busy!\n");
      return CU_SOFTMAC_MAC_NOTIFY_BUSY;
    }
    /*
     * Check to see if we're supposed to defer transmission to the tasklet
     */
    if (inst->defertx) {
      /*
       * Queue the packet in tx_skbqueue, tell the SoftMAC to run us again
       */
      status = CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN;
    }
    else {
      /*
       * Send the packet now, don't have the SoftMAC run us again
       */

      /*
       * XXX use of atheros-specific PHY calls!!!
       */
      cu_softmac_ath_set_default_phy_props(nfh,packet);
      cu_softmac_ath_set_tx_bitrate(nfh,packet,inst->txbitrate);

      (inst->myphy.cu_softmac_sendpacket)(nfh,inst->maxinflight,packet);
      status = CU_SOFTMAC_MAC_NOTIFY_OK;
    }
    spin_unlock(&(inst->mac_busy));
  }
  else {
    /*
     * Could not get our instance handle -- let the PHY layer know...
     */
    printk(KERN_EMERG "CheesyMAC: packet_tx -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
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
    if (spin_trylock(&(inst->mac_busy))) {
      /*
       * If we can't get the lock tell the PHY layer we're busy...
       */
      return CU_SOFTMAC_MAC_NOTIFY_BUSY;
    }
    /*
     * Check to see if we're supposed to defer handling
     */
    if (inst->defertxdone) {
      /*
       * Queue the packet in txdone_skbqueue, schedule the tasklet
       * XXX implement this!
       */
      status = CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN;
    }
    else {
      /*
       * Free the packet immediately, do not run again
       */
      if (packet) {
	(inst->myphy.cu_softmac_free_skb)(nfh,packet);
	packet = 0;
      }
      status = CU_SOFTMAC_MAC_NOTIFY_OK;
    }
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_EMERG "CheesyMAC: packet_tx_done -- no instance handle!\n");
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
    /*
     * XXX the "netif_rx" function is an OS thing, not phy layer...
     */
    if (spin_trylock(&(inst->mac_busy))) {
      return CU_SOFTMAC_MAC_NOTIFY_BUSY;
    }

    /*
     * Just send the packet up the network stack
     */
    (inst->myphy.cu_softmac_netif_rx_ether)(nfh,packet);
  }
  else {
    printk(KERN_EMERG "CheesyMAC: packet_rx -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }

  return status;
}

static int cu_softmac_mac_work_cheesymac(CU_SOFTMAC_PHY_HANDLE nfh,
					 void* mydata, int intop) {
  CHEESYMAC_INSTANCE* inst = mydata;
  int status = CU_SOFTMAC_MAC_NOTIFY_OK;

  if (inst) {
    /*
     * The CheesyMAC doesn't have any work to do...
     */
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
    spin_lock(&(inst->mac_busy));
    /*
     * The PHY layer has finished detaching us -- make sure we don't
     * use it any more.
     */
    
    /*
     * First verify that we're actually attached to some phy layer...
     */
    if (0 == atomic_read(&(inst->attached_to_phy))) {
      printk(KERN_EMERG "SoftMAC CheesyMAC: Received a detach notification while not attached!\n");
      status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
    }
    else {
      atomic_set(&(inst->attached_to_phy),0);
    }
    spin_unlock(&(inst->mac_busy));
    // XXX finish this
  }
  else {
    printk(KERN_EMERG "CheesyMAC: mac_detach -- no instance handle!\n");
    status = CU_SOFTMAC_MAC_NOTIFY_HOSED;
  }
  return status;
}

static int cu_softmac_cheesymac_destroy_instance(void* mypriv) {
  CHEESYMAC_INSTANCE* inst = mypriv;
  if (inst) {
    CHEESYMAC_INSTANCE* nextinst = 0;
    /*
     * Detach/delete this cheesymac instance
     */
    if (inst == my_softmac_instances) {
      /*
       * Is this the list head? Check and see if there's a replacement.
       * If this is the only item in the list just set the head
       * to 0.
       */
      nextinst = list_entry(inst->list.next,CHEESYMAC_INSTANCE,list);
      if (inst != nextinst) {
	my_softmac_instances = nextinst;
      }
      else {
	my_softmac_instances = 0;
      }
    }
    list_del(&(inst->list));
    cheesymac_cleanup_instance(inst);
    kfree(inst);
    inst = 0;
  }
  return 0;
}

static int
cu_softmac_cheesymac_create_instance(CU_SOFTMAC_PHYLAYER_INFO* phyinfo,
				     CU_SOFTMAC_MACLAYER_INFO* macinfo) {
  int result = 0;
  CHEESYMAC_INSTANCE* newinst = 0;

  /*
   * Create a new instance, make it part of a kernel linked list
   */
  newinst = kmalloc(sizeof(CHEESYMAC_INSTANCE),GFP_ATOMIC);
  if (newinst) {
    memset(newinst,0,sizeof(CHEESYMAC_INSTANCE));
    INIT_LIST_HEAD(&newinst->list);

    if (!my_softmac_instances) {
      my_softmac_instances = newinst;
    }
    else {
      list_add_tail(&newinst->list,&my_softmac_instances->list);
    }
    
    /*
     * If we got a pointer to PHY layer info make a copy of it
     */
    if (phyinfo) {
      memcpy(&(newinst->myphy),phyinfo,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
    }

    /*
     * Our mac private info is a pointer to a cheesymac instance
     */
    macinfo->mac_private = newinst;
    
    /*
     * Fire up the instance...
     */

    cheesymac_setup_instance(phyinfo,newinst,macinfo);
  }
  else {
    printk(KERN_EMERG "CheesyMAC create_instance: Unable to allocate memory!\n");
    result = -1;
  }

  return result;
}

static int
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
  /*
   * XXX need to set the "options" field correctly
   */
  macinfo->options = 0;
  macinfo->mac_private = macpriv;

  return result;
}

static int cheesymac_setup_instance(CU_SOFTMAC_PHYLAYER_INFO* phyinfo,
				    CHEESYMAC_INSTANCE* newinst,
				    CU_SOFTMAC_MACLAYER_INFO* macinfo) {
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
  spin_lock(&cheesymac_instanceid_lock);
  newinst->instanceid = cheesymac_next_instanceid;
  cheesymac_next_instanceid++;
  spin_unlock(&cheesymac_instanceid_lock);
  atomic_set(&(newinst->attached_to_phy),0);
  newinst->txbitrate = cheesymac_defaultbitrate;
  newinst->defertx = cheesymac_defertx;
  newinst->defertxdone = cheesymac_defertxdone;
  newinst->deferrx = cheesymac_deferrx;
  newinst->maxinflight = cheesymac_maxinflight;

  /*
   * Initialize our packet queues
   */
  skb_queue_head_init(&(newinst->tx_skbqueue));
  skb_queue_head_init(&(newinst->txdone_skbqueue));
  skb_queue_head_init(&(newinst->rx_skbqueue));

  /*
   * Load up the function table so that the SoftMAC layer can
   * communicate with us.
   */
  cu_softmac_cheesymac_get_macinfo(newinst,macinfo);

  /*
   * XXX
   * Create procfs entries
   */
  spin_unlock(&(newinst->mac_busy));
  return result;
}

static int
cu_softmac_mac_attach_to_phy_cheesymac(void* handle,
				       CU_SOFTMAC_PHYLAYER_INFO* phyinfo) {
  CHEESYMAC_INSTANCE* inst = handle;
  int result = 0;
  if (inst && phyinfo) {
    CU_SOFTMAC_MACLAYER_INFO cheesymacinfo;
    printk(KERN_EMERG "SoftMAC CheesyMAC: Attaching to PHY -- getting lock\n");
    spin_lock(&(inst->mac_busy));
    printk(KERN_EMERG "SoftMAC CheesyMAC: Attaching to PHY -- got lock\n");
    if (0 != atomic_read(&(inst->attached_to_phy))) {
      /*
       * Already attached -- bail out
       */
      printk(KERN_EMERG "SoftMAC CheesyMAC: Attempting to attach to a phy layer while still attached to a phy layer!\n");
      result = -1;
    }
    else {
      /*
       * Set the phy info and then attach a cheesymac instance
       */

      atomic_set(&(inst->attached_to_phy),1);
      cu_softmac_cheesymac_set_phyinfo(handle,phyinfo);
      cu_softmac_cheesymac_get_macinfo(handle,&cheesymacinfo);
      printk(KERN_EMERG "SoftMAC CheesyMAC: About to call PHY attach\n");
      (phyinfo->cu_softmac_attach_mac)(phyinfo->phyhandle,&cheesymacinfo);
      printk(KERN_EMERG "SoftMAC CheesyMAC: Return from PHY attach\n");
    }
    printk(KERN_EMERG "SoftMAC CheesyMAC: Unlocking MAC\n");
    spin_unlock(&(inst->mac_busy));
  }
  else {
    printk(KERN_EMERG "SoftMAC CheesyMAC: Invalid MAC/PHY data on attach!\n");
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
    if (0 == atomic_read(&(inst->attached_to_phy))) {
      printk(KERN_EMERG "SoftMAC CheesyMAC: Received a detach request while not attached -- NOP\n");
      /*
       * This isn't so much an error as it is a NOP
       */
      result = 0;
    }
    else {
      /*
       * Explicitly force the phy layer to detach us.
       */
      (inst->myphy.cu_softmac_detach_mac)(inst->myphy.phyhandle,inst);
    }
  }

  return result;
}

static int cheesymac_cleanup_instance(CHEESYMAC_INSTANCE* inst) {
  int result = 0;
  struct sk_buff* skb = 0;

  /*
   * Clean up after a CheesyMAC instance
   */

  spin_lock(&(inst->mac_busy));


  /*
   * XXX
   * remove procfs entries
   */

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

static int
cu_softmac_cheesymac_set_phyinfo(void* mypriv,
				 CU_SOFTMAC_PHYLAYER_INFO* pinfo) {
  int result = 0;
  if (mypriv) {
    CHEESYMAC_INSTANCE* inst = mypriv;
    spin_lock(&(inst->mac_busy));
    memcpy(&(inst->myphy),pinfo,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
    spin_unlock(&(inst->mac_busy));
    result = 0;
  }
  else {
    result = -1;
  }
  return result;
}

module_init(softmac_cheesymac_init);
module_exit(softmac_cheesymac_exit);

EXPORT_SYMBOL(cu_softmac_cheesymac_create_instance);
EXPORT_SYMBOL(cu_softmac_cheesymac_destroy_instance);
EXPORT_SYMBOL(cu_softmac_cheesymac_set_phyinfo);
EXPORT_SYMBOL(cu_softmac_cheesymac_get_macinfo);

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
