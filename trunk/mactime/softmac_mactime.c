/*
 * softmac_mactime.c
 * SoftMAC functions for handling timed packet sending, e.g.
 * choreographed packet patterns or TDMA
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include "../cu_softmac_api.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");


typedef struct {
  struct list_head list;
  CU_SOFTMAC_NETIF_HANDLE mynfh;

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
} SOFTMAC_MACTIME_INSTANCE;

/*
 * The MACTime module presents sendpacket functions to be used by
 * the client MAC layer.
 */

/*
 * Send a packet, only permitting max_packets_inflight to be pending
 */
int
cu_softmac_sendpacket_mactime(CU_SOFTMAC_NETIFHANDLE nfh,
			      int max_packets_inflight,struct sk_buff* skb) {
}

/*
 * Send a packet, only permitting max_packets_inflight to be pending.
 * Do NOT free the sk_buff upon failure. This allows callers to do things
 * like requeue a packet if they care to make another attempt to send the
 * packet that failed to go out.
 */
int cu_softmac_sendpacket_keepskbonfail_mactime(CU_SOFTMAC_NETIFHANDLE nfh,
						int max_packets_inflight,
						struct sk_buff* skb) {
}

/*
 * Notify the MAC layer that a packet transmit has completed -- exported
 * via pointer as "cu_softmac_packet_tx_done" to the SoftMAC PHY.
 * The MACTime module interposes itself between the PHY and "client"
 * MAC layer so that it can keep precise track of packets and timing.
 */
static int
cu_softmac_packet_tx_done_mactime(CU_SOFTMAC_NETIFHANDLE nfh,
				  void* mydata,
				  struct sk_buff* packet,
				  int intop) {
}

/*
 * The MACTime module interposes itself between the PHY and "client"
 * MAC layer "work" callback so that it can schedule itself to 
 * run as required to try to meet desired packet timing constraints.
 */
static int
cu_softmac_work_mactime(CU_SOFTMAC_NETIFHANDLE nfh,void* mydata, int intop) {
  
}

static int __init softmac_mactime_init(void)
{
  printk(KERN_ALERT "Loading SoftMAC MACTime module\n");
  return 0;
}

static void __exit softmac_mactime_exit(void)
{
  printk(KERN_ALERT "Unloading SoftMAC MACTime module\n");
}

static int cu_softmac_create_instance_mactime(CU_SOFTMAC_NETIFHANDLE nfh,CU_SOFTMAC_CLIENT_INFO* clientinfo) {
  int result = 0;
  SOFTMAC_MACTIME_INSTANCE* newinst = 0;

  /*
   * Create a new instance, make it part of a kernel linked list
   */
  newinst = kmalloc(sizeof(SOFTMAC_MACTIME_INSTANCE),GFP_ATOMIC);
  if (newinst) {
    memset(newinst,0,sizeof(SOFTMAC_MACTIME_INSTANCE));
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
				    SOFTMAC_MACTIME_INSTANCE* inst,
				    CU_SOFTMAC_CLIENT_INFO* clientinfo) {
  int result = 0;
  /*
   * Set up a MACTime instance
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
				      SOFTMAC_MACTIME_INSTANCE* inst) {
  int result = 0;
  struct sk_buff* skb = 0;

  /*
   * Clean up after a MACTime instance
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


module_init(softmac_mactime_init);
module_exit(softmac_mactime_exit);
