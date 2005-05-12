/*
 * softmac_netif.c
 * SoftMAC functions for creating a network interface
 */
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include "../cu_softmac_api.h"
#include "softmac_netif.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michael Neufeld");



static int __init softmac_netif_init(void)
{
  printk(KERN_ALERT "Loading SoftMAC netif module\n");
  return 0;
}

static void __exit softmac_netif_exit(void)
{
  printk(KERN_ALERT "Unloading SoftMAC netif module\n");
}

module_init(softmac_netif_init);
module_exit(softmac_netif_exit);
