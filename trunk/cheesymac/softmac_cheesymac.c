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
#include "cu_softmac_api.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");

typedef struct {
  struct list_head list;
  CU_SOFTMAC_NETIF_HANDLE mynfh;
  unsigned char txbitrate;
} CHEESYMAC_INSTANCE;

static CHEESYMAC_INSTANCE* my_softmac_instances = 0;

#if 0
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

static int __init softmac_cheesymac_init(void)
{
#if 0
	printk(KERN_ALERT "Hello, world 5\n=============\n");
	printk(KERN_ALERT "myshort is a short integer: %hd\n", myshort);
	printk(KERN_ALERT "myint is an integer: %d\n", myint);
	printk(KERN_ALERT "mylong is a long integer: %ld\n", mylong);
	printk(KERN_ALERT "mystring is a string: %s\n", mystring);
#endif
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
	  struct list_head* p = 0;
	  
	  list_for_each(p,my_softmac_instances->list) {
	    cheesy_instance = list_entry(p,CHEESYMAC_INSTANCE,list);
	    cu_softmac_detach_mac(cheesy_instance->mynfh,cheesy_instance);
	  }
	}
}

static int cu_softmac_packet_tx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet, int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  int runagain = 0;

  if (myinstance) {
    cu_softmac_sendpacket(nfh,256,packet);
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
    if (packet) {
      cu_softmac_free_skb(nfh,packet);
      packet = 0;
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
  }

  return runagain;
}

static int cu_softmac_detach_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				       void* mydata, int intop) {
  CHEESYMAC_INSTANCE* myinstance = mydata;
  if (myinstance) {
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
    newinst->txbitrate = 2;
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
