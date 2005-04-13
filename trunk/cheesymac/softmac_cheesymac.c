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
	printk(KERN_ALERT "Goodbye, world 5\n");
}

static int cu_softmac_packet_tx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet, int intop) {
  int runagain = 0;

  return runagain;
}


static int cu_softmac_packet_tx_done_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
						void* mydata,
						struct sk_buff* packet,
						int intop) {
  int runagain = 0;

  return runagain;
}


static int cu_softmac_packet_rx_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
					  void* mydata,
					  struct sk_buff* packet,
					  int intop) {
  int runagain = 0;

  return runagain;
}

static int cu_softmac_work_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				     void* mydata, int intop) {
  int runagain = 0;

  return runagain;
}

static int cu_softmac_detach_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh,
				       void* mydata, int intop) {

  return 0;
}


static int cu_softmac_create_instance_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh) {
}

static int cu_softmac_set_netifhandle_cheesymac(CU_SOFTMAC_NETIFHANDLE nfh) {
}

module_init(softmac_cheesymac_init);
module_exit(softmac_cheesymac_exit);
