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

typedef struct {
  struct list_head list;
  CU_SOFTMAC_NETIF_HANDLE mynfh;
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
} CHEESYMAC_INSTANCE;

static CHEESYMAC_INSTANCE* my_softmac_instances = 0;

static int cheesymac_defaultbitrate;
static int cheesymac_defertx;
static int cheesymac_defertxdone;
static int cheesymac_deferrx;
static int cheesymac_maxinflight;
static int cheesymac_deferallrx;
static int cheesymac_deferalltxdone;

module_param(cheesymac_defertx, int, 0644);
MODULE_PARM_DESC(cheesymac_defertx, "Queue packets and defer transmit to tasklet");
module_param(cheesymac_defertxdone, int, 0644);
MODULE_PARM_DESC(cheesymac_defertxdone, "Queue packets that are finished transmitting and defer handling to tasklet");
module_param(cheesymac_deferrx, int, 0644);
MODULE_PARM_DESC(cheesymac_deferrx, "Queue received packets and defer handling to tasklet");
module_param(cheesymac_maxinflight, int, 0644);
MODULE_PARM_DESC(cheesymac_maxinflight, "Limit the number of packets allowed to be in the pipeline for transmission");

/*
 * XXX Finish setting default values for module params!
 */

static int __init softmac_cheesymac_init(void)
{
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
    // We're booted -- kill off the instance
    list_del(myinstance->list);
    kfree(myinstance);
    myinstance = 0;
  }
  return 0;
}

static int cu_softmac_create_instance_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,CU_SOFTMAC_CLIENT_INFO* clientinfo) {
  int result = 0;
  CHEESYMAC_INSTANCE* newinst = 0;

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
    clientinfo->client_private = newinst;
    newinst->mynfh = nfh;
    newinst->txbitrate = cheesymac_defaultbitrate;
    set_cheesymac_functions(clientinfo);
  }
  else {
    result = -1;
  }

  return result;
}

static int cu_softmac_set_netifhandle_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,void* mypriv) {
  int result = 0;
  if (mypriv) {
    CHEESYMAC_INSTANCE* myinst = mypriv;
    myinst->mynfh= nfh;
    result = 0;
  }
  else {
    result = -1;
  }
  return result;
}

static void set_cheesymac_functions(CU_SOFTMAC_CLIENT_INFO* clientinfo) {
  clientinfo->cu_softmac_packet_tx = cu_softmac_packet_tx_cheesymac;
  clientinfo->cu_softmac_packet_tx_done = cu_softmac_packet_tx_done_cheesymac;
  clientinfo->cu_softmac_packet_rx = cu_softmac_packet_rx_cheesymac;
  clientinfo->cu_softmac_work = cu_softmac_work_cheesymac;
  clientinfo->cu_softmac_detach = cu_softmac_detach_cheesymac;
}
module_init(softmac_cheesymac_init);
module_exit(softmac_cheesymac_exit);

EXPORT_SYMBOL(cu_softmac_create_instance_cheesymac);


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
