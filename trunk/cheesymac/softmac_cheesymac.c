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
#include "cu_softmac_api.h"

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
}


typedef struct {
  struct list_head list;
  CU_SOFTMAC_PHYLAYER_INFO myphy;
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
 
  /*
   * XXX spinlocking?
   */
  spinlock_t instance_busy;
} CHEESYMAC_INSTANCE;

/*
 * Declarations of functions used internally and/or exported
 */

/*
 * Create a CheesyMAC instance -- exported for multiple MAC layer support
 * (MixMAC, FlexiMAC, MACsalot, MACsploitation)????
 */
static int
cu_softmac_create_instance_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				     CU_SOFTMAC_CLIENT_INFO* clientinfo);
/*
 * Set the SoftMAC PHY handle to use in an instance -- exported for multiple
 * MAC layer support
 */
static int
cu_softmac_set_phyinfo_cheesymac(void* mypriv,CU_SOFTMAC_PHYLAYER_INFO* pinfo);

/*
 * Notify the MAC layer that it is being removed from the PHY -- exported
 * via pointer as "cu_softmac_detach" to the SoftMAC PHY
 */
static int
cu_softmac_detach_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,void* mydata,int intop);

/*
 * Notify the MAC layer that it is time to do some work -- exported
 * via pointer as "cu_softmac_work" to the SoftMAC PHY
 */
static int
cu_softmac_work_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
			  void* mydata, int intop);

/*
 * Notify the MAC layer that a packet has been received -- exported
 * via pointer as "cu_softmac_packet_rx" to the SoftMAC PHY
 */
static int
cu_softmac_packet_rx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
			       void* mydata,
			       struct sk_buff* packet,
			       int intop);

/*
 * Notify the MAC layer that a packet transmit has completed -- exported
 * via pointer as "cu_softmac_packet_tx_done" to the SoftMAC PHY
 */
static int
cu_softmac_packet_tx_done_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				    void* mydata,
				    struct sk_buff* packet,
				    int intop);

/*
 * Notify the MAC layer that an ethernet-encapsulated packet
 * has been received from up the protocol stack -- exported
 * via pointer as "cu_softmac_packet_tx" to the SoftMAC PHY
 */
static int
cu_softmac_packet_tx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
			       void* mydata,
			       struct sk_buff* packet, int intop);


/*
 * Do cleanup when shutting down a CheesyMAC instance -- internal utility
 */
static int
cheesymac_cleanup_instance(CU_SOFTMAC_NETIFHANDLE nfh,
			   CHEESYMAC_INSTANCE* inst);

/*
 * Do initialization when creating a CheesyMAC instance -- internal utility
 */
static int
cheesymac_setup_instance(CU_SOFTMAC_NETIFHANDLE nfh, CHEESYMAC_INSTANCE* inst,
			 CU_SOFTMAC_CLIENT_INFO* clientinfo);



/*
 * Keep a reference to the head of our linked list of instances
 */
static CHEESYMAC_INSTANCE* my_softmac_instances = 0;

/*
 * First instance ID to use is 1
 * XXX initialize this
 */
static atomic_t cheesymac_next_instanceid;
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
 * Optionally attach the cheesymac to the softmac upon loading
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
  printk(KERN_ALERT "Loading CheesyMAC\n");
  if (cheesymac_attach_on_load) {
    CU_SOFTMAC_CLIENT_INFO newclientinfo;
    CU_SOFTMAC_PHYLAYER_INFO athphyinfo;
    struct net_device* mydev = 0;
    printk(KERN_ALERT "Creating and attaching CheesyMAC to Atheros SoftMAC on %s\n",cheesymac_defaultphy);
    mydev = dev_get_by_name(cheesymac_defaultphy);
    /*
     * Got the device handle, now attempt to get phy info off of it
     */
    if (mydev) {
      cu_softmac_ath_get_phyinfo(mydev,&athphyinfo);
      memset(&newclientinfo,0,sizeof(CU_SOFTMAC_CLIENT_INFO));
      /*
       * Create an instance of CheesyMAC that we will then attach
       * to the atheros phy layer using the attach function inside
       * of the atheros phy info structure we got earlier.
       */
      if (cu_softmac_create_instance_cheesymac(0,newclientinfo)) {
	
	athphyinfo->cu_softmac_attach_mac(athphyinfo->phyhandle,&newclientinfo);
	
	
	//int cu_softmac_set_netifhandle_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,void* mypriv);
      }
      else {
	printk(KERN_ALERT "CheesyMAC: Unable to create instance of self!\n",cheesymac_defaultphy);
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
  printk(KERN_ALERT "Unloading CheesyMAC\n");
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
    list_for_each_safe(p,tmp,my_softmac_instances->list) {
      cheesy_instance = list_entry(p,CHEESYMAC_INSTANCE,list);
      list_del(p);
      cu_softmac_detach_mac(cheesy_instance->mynfh,cheesy_instance);
      cheesymac_cleanup_instance(cheesy_instance->mynfh,cheesy_instance);
      kfree(cheesy_instance);
    }
  }
}

static int cu_softmac_packet_tx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet, int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  int runagain = 0;

  if (myinstance) {
    /*
     * Check to see if we're supposed to defer transmission to the tasklet
     */
    if (myinstance->defertx) {
      /*
       * Queue the packet in tx_skbqueue, tell the SoftMAC to run us again
       */
      runagain = 1;
    }
    else {
      /*
       * Send the packet now, don't have the SoftMAC run us again
       */
      cu_softmac_set_default_phy_props(nfh,packet);
      cu_softmac_set_tx_bitrate(nfh,packet,myinstance->txbitrate);
      cu_softmac_sendpacket(nfh,myinstance->maxinflight,packet);
      runagain = 0;
    }
  }
  else {
    /*
     * Could not get our instance handle -- free
     * the packet and get on with life.
     */
    printk(KERN_ALERT "CheesyMAC: packet_tx -- no instance handle!\n");
    cu_softmac_free_skb(nfh,packet);
  }

  return runagain;
}

static int cu_softmac_packet_tx_done_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
						void* mydata,
						struct sk_buff* packet,
						int intop) {
  int runagain = 0;
  CHEESYMAC_INSTANCE* myinstance = mydata;

  if (myinstance) {
    /*
     * Check to see if we're supposed to defer handling
     */
    if (myinstance->defertxdone) {
      /*
       * Queue the packet in txdone_skbqueue, schedule the tasklet
       */
      runagain = 1;
    }
    else {
      /*
       * Free the packet immediately, do not run again
       */
      if (packet) {
	cu_softmac_free_skb(nfh,packet);
	packet = 0;
      }
      runagain = 0;
    }
  }

  return runagain;
}


static int cu_softmac_packet_rx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet,
					  int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  int runagain = 0;

  if (myinstance) {
    cu_softmac_netif_rx_ether(nfh,packet);
  }

  return runagain;
}

static int cu_softmac_work_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				     void* mydata, int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  int runagain = 0;

  if (myinstance) {
    /*
     * The CheesyMAC doesn't have any work to do...
     */
  }

  return runagain;
}

static int cu_softmac_detach_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				       void* mydata, int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  if (myinstance) {
    /*
     * Detach/delete this cheesymac instance
     */
    if (myinstance == my_softmac_instance) {
      /*
       * Is this the list head? Check and see if there's a replacement.
       * If this is the only item in the list just set the head
       * to 0.
       */
      if (myinstance != myinstance->list->next) {
	my_softmac_instance = list_entry(myinstance->list->next,CHEESYMAC_INSTANCE,list);
      }
      else {
	my_softmac_instance = 0;
      }
    }
    list_del(myinstance->list);
    cheesymac_cleanup_instance(nfh,myinstance);
    kfree(myinstance);
    myinstance = 0;
  }
  return 0;
}

static int cu_softmac_create_instance_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,CU_SOFTMAC_CLIENT_INFO* clientinfo) {
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
     * Our client private info is a pointer to a cheesymac instance
     */
    newinst->mynfh = nfh;
    clientinfo->client_private = newinst;
    
    /*
     * Fire up the instance...
     */
    cheesymac_setup_instance(nfh,newinst,clientinfo);
  }
  else {
    result = -1;
  }

  return result;
}

static int cheesymac_setup_instance(CU_SOFTMAC_NETIFHANDLE nfh,
				    CHEESYMAC_INSTANCE* inst,
				    CU_SOFTMAC_CLIENT_INFO* clientinfo) {
  int result = 0;
  /*
   * Set up a CheesyMAC instance
   */
  /*
   * XXX locking?
   */

  /*
   * Set our instance default parameter values
   */
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
  clientinfo->cu_softmac_packet_tx = cu_softmac_packet_tx_cheesymac;
  clientinfo->cu_softmac_packet_tx_done = cu_softmac_packet_tx_done_cheesymac;
  clientinfo->cu_softmac_packet_rx = cu_softmac_packet_rx_cheesymac;
  clientinfo->cu_softmac_work = cu_softmac_work_cheesymac;
  clientinfo->cu_softmac_detach = cu_softmac_detach_cheesymac;

  /*
   * XXX
   * Create procfs entries
   */

  return result;
}

static int cheesymac_cleanup_instance(CU_SOFTMAC_NETIFHANDLE nfh,
				      CHEESYMAC_INSTANCE* inst) {
  int result = 0;
  struct sk_buff* skb = 0;

  /*
   * Clean up after a CheesyMAC instance
   */


  /*
   * XXX
   * remove procfs entries
   */

  /*
   * Drain queues...
   */
  while (skb = skb_dequeue(&(inst->tx_skbqueue))) {
    cu_softmac_free_skb(nfh,skb);
  }
  while (skb = skb_dequeue(&(inst->txdone_skbqueue))) {
    cu_softmac_free_skb(nfh,skb);
  }
  while (skb = skb_dequeue(&(inst->rx_skbqueue))) {
    cu_softmac_free_skb(nfh,skb);
  }

  return result;
}

static int cu_softmac_set_phyinfo_cheesymac(void* mypriv,CU_SOFTMAC_PHYLAYER_INFO* pinfo) {
  int result = 0;
  if (mypriv) {
    CHEESYMAC_INSTANCE* myinst = mypriv;
    memcpy(&(myinst->myphy),pinfo,sizeof(CU_SOFTMAC_PHYLAYER_INFO));
    result = 0;
  }
  else {
    result = -1;
  }
  return result;
}

module_init(softmac_cheesymac_init);
module_exit(softmac_cheesymac_exit);

EXPORT_SYMBOL(cu_softmac_create_instance_cheesymac);
EXPORT_SYMBOL(cu_softmac_set_phyinfo_cheesymac);

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
