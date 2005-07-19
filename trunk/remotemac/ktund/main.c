/*
 * kathd 
 *
 * 1/2005 Initial Version - Jeff Fifield
 *
 * some code taken from khttpd
 *
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include "ktund.h"
#include "cu_softmac_api.h"

#define NAME "ktund"

#define DEFAULT_SERVER_PORT    4321
#define DEFAULT_SERVER_NAME    "192.168.0.2"

char ktund_server_name[256];
int  ktund_server_port;

int ktund_start;
int ktund_stop;
int ktund_unload;
atomic_t ktund_stop_count;

static struct socket *server_sock;

#define RX_BUF_SIZE 4096
static unsigned char *rx_buf;

/* we may not get all bytes of a packet at once.
   rx_leftover_bytes indicates the number of bytes 
   still sitting in rx_buf[] from a previous recvmsg */
static int rx_leftover_bytes;

/* ath/if_ath.c */
extern struct sk_buff *remotemac_alloc_skb(void *priv, u_int size);

/* host -> net */
static int
ktund_tunnel_tx(char *data, int len)
{
    struct msghdr msg;
    struct kvec kv[3];
    struct ktund_packet_hdr *pkt_hdrp;
    struct ktund_packet_hdr pkt_hdr;
    int kv_len;

    if (!server_sock) {
	printk(NAME ":%s !server_sock\n", __func__ );
	return -ENETDOWN;
    }
    server_sock->sk->sk_allocation = GFP_ATOMIC;

    // XXX should use a work queue since probably get called by top half or tasklet

    /* if some other code, ktund_tunnel_rx for example, currently
       has the socket locked and we are in interrupt context, tcp
       will try to lock the socket, then sleep, then kernel panic  */
    if ((sock_owned_by_user(server_sock->sk) != 0) && in_interrupt()) {
	/*printk(NAME ":%s would block in intr!\n", __func__ );*/
	return -EAGAIN;
    }

    memset(&msg, 0, sizeof(msg));
    msg.msg_flags  = MSG_NOSIGNAL | MSG_DONTWAIT;
    
    pkt_hdrp = (struct ktund_packet_hdr *)data;
    if (pkt_hdrp->sync != KTUND_SYNC) {
	/* build the packet header */
	memset(&pkt_hdr, 0, sizeof(pkt_hdr));
	pkt_hdr.sync = KTUND_SYNC;
	pkt_hdr.ctl_len = 0;
	pkt_hdr.data_len = len;

	kv[0].iov_base = (char *)&pkt_hdr;
	kv[0].iov_len  = sizeof(struct ktund_packet_hdr);
	kv[1].iov_base = data;
	kv[1].iov_len  = len;
	kv_len = 2;
	len = sizeof(struct ktund_packet_hdr) + pkt_hdr.ctl_len + pkt_hdr.data_len;
    } else {
	/* header already exists */
	kv[0].iov_base = data;
	kv[0].iov_len  = len;
	kv_len = 1;
    }

    /* send packet */
    return kernel_sendmsg(server_sock, &msg, kv, kv_len, len);
}

static int
ktund_tunnel_txskb(void *p, struct sk_buff *skb)
{        
    int ret;

    ret = ktund_tunnel_tx(skb->data, skb->len);
    if (ret < 0 && ret != -EAGAIN)
	printk(NAME ":%s error %d\n", __func__, -ret);

    kfree_skb(skb);
    return ret;
}

/* net -> host, return 0 if the connection was closed, 1 otherwise */
static int
ktund_tunnel_rx(CU_SOFTMAC_MACLAYER_INFO *remotemac)
{
    int pkt_len, len;
    struct sk_buff *skb;
    struct ktund_packet_hdr *pkt_hdr;
    struct msghdr msg;
    struct kvec kv;
    unsigned char *buf;

    if (!server_sock)
	return 0;

    server_sock->sk->sk_allocation = GFP_ATOMIC;

    memset(&msg, 0, sizeof(msg));
    msg.msg_flags = MSG_NOSIGNAL | MSG_DONTWAIT;
    kv.iov_base = rx_buf + rx_leftover_bytes;
    kv.iov_len = RX_BUF_SIZE - rx_leftover_bytes;

    len = kernel_recvmsg(server_sock, &msg, &kv, 1, kv.iov_len, 0);
    if (len <= 0) {
	if (len == -EAGAIN)
	    return 1;
	else
	    return 0;
    }

    /* always eat leftovers, else they go bad */
    len += rx_leftover_bytes;
    rx_leftover_bytes = 0;

    /* recvmsg may return multiple packets */
    buf = rx_buf;
    while (len >= sizeof(struct ktund_packet_hdr)) {

	/* check that it's a valid packet header */
 	pkt_hdr = (struct ktund_packet_hdr *)buf;
	if (pkt_hdr->sync != KTUND_SYNC) {
	    printk(NAME ": bad sync number %08x\n", pkt_hdr->sync);
	    return 1;
	}

	/* check that we have all the data */
	pkt_len = sizeof(struct ktund_packet_hdr) + pkt_hdr->ctl_len + pkt_hdr->data_len;
	if (pkt_len > len) {
	    /*printk(NAME ": incomplete packet %d > %d\n", pkt_len, len);*/
	    break;
	}
	
	/*printk(NAME ": got %d bytes of control, %d bytes of data\n",
	  pkt_hdr->ctl_len, pkt_hdr->data_len);*/

	/* successfully received a packet... send it to softmac */
	//skb = ath_cu_remote_alloc_skb(dev, pkt_len + 32);
	skb = remotemac_alloc_skb(remotemac->mac_private, pkt_len + 32);
	if (!skb) {
	    printk(NAME ": remotemac_alloc_skb failed\n");
	    return 1;
	}
	skb_reserve(skb, 32);

#if 0
	/* strip the sync */
	memcpy(skb->data, buf + sizeof(pkt_hdr->sync), pkt_len - sizeof(pkt_hdr->sync));
	skb_put(skb, pkt_len - sizeof(pkt_hdr->sync));
#else
	/* dont strip the sync */
	memcpy(skb->data, buf, pkt_len);
	skb_put(skb, pkt_len);
#endif
	//ath_cu_remote_tx(dev, skb);
	remotemac->cu_softmac_mac_packet_tx(remotemac->mac_private, skb, 0);

	buf += pkt_len;
	len -= pkt_len;
    }

    if (len) {
	/* put away the leftovers */
	if (rx_buf != buf)
	    memmove(rx_buf, buf, len);
	rx_leftover_bytes = len;
    }
    return 1;
}

/* tunnel client */
static int
ktund_tunnel_main(void *v)
{
    struct socket *sock;
    struct sockaddr_in in_addr;
    int connected;
    int ret;
    int old_stop_count;
    CU_SOFTMAC_MACLAYER_INFO *remotemac;
    CU_SOFTMAC_PHYLAYER_INFO *athphy;
    DECLARE_WAIT_QUEUE_HEAD(waitq);

    __module_get(THIS_MODULE);

    daemonize(NAME"_tunnel_main");

    sock = 0;
    old_stop_count = atomic_read(&ktund_stop_count);
    
    /* get a page (4096 bytes) of recv buffer memory */
    rx_buf = (char *)kmalloc(RX_BUF_SIZE, GFP_KERNEL);
    if (rx_buf == 0) {
	printk(NAME ":%s not enough memory\n", __func__);
	module_put(THIS_MODULE);
	return 0;
    }

    /* main loop of tunnel thread */
    while (old_stop_count == atomic_read(&ktund_stop_count)) {
	//sprintf(current->comm, "ktund tunnel");

	/* create the socket */
	/* tcp */
	ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	/* udp */
	//ret = sock_create(PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret < 0) {
	    printk(NAME ": tunnel sock_create error %d\n", ret);
	    module_put(THIS_MODULE);
	    return 0;
	}

	/* connect to: ip = ktund_server_name, port = ktund_server_port */
	connected = 0;
	while (!connected && old_stop_count == atomic_read(&ktund_stop_count)) {
	    
	    in_addr.sin_family = AF_INET;
	    in_addr.sin_port = htons(ktund_server_port);
	    in_addr.sin_addr.s_addr = in_aton(ktund_server_name);
	    printk(NAME ": tunnel connecting to %s\n", ktund_server_name);
	    
	    ret = sock->ops->connect(sock, (struct sockaddr *)&in_addr, sizeof(in_addr), 0);
	    if (ret < 0) {
		printk(NAME ": tunnel connect error %d\n", ret);
		interruptible_sleep_on_timeout(&waitq, HZ);
	    } else {
		connected = 1;
		printk(NAME ": tunnel connected to %s\n", ktund_server_name);
	    }
	}
	if (!connected) 
	    break;

	/* connected */
	server_sock = sock;
	rx_leftover_bytes = 0;
	
	/* register with softmac */
#if 0
	ath_dev = dev_get_by_name("ath0");
	if (!ath_dev) {
	    printk(NAME ": device ath0 not found\n");
	    module_put(THIS_MODULE);
	    return 0;
	}
	ath_cu_remote_register_rx_func(ath_dev, ktund_tunnel_txskb, 0);
#endif
	athphy = cu_softmac_phyinfo_get_by_name("athphy0");
	if (!athphy)
	    athphy = cu_softmac_phyinfo_get( cu_softmac_layer_new_instance("athphy") );
	if (!athphy) {
	    printk(NAME "%s error couldn't get phy instance!\n", __func__);
	    module_put(THIS_MODULE);
	    return 0;
	}

	remotemac = cu_softmac_macinfo_get_by_name("remotemac0");
	if (!remotemac)
	    remotemac = cu_softmac_macinfo_get( cu_softmac_layer_new_instance("remotemac") );
	if (!remotemac) {
	    printk(NAME "%s error couldn't get mac instance!\n", __func__);
	    module_put(THIS_MODULE);
	    return 0;
	}
	remotemac->cu_softmac_mac_set_rx_func(remotemac->mac_private, ktund_tunnel_txskb, 0);
	remotemac->cu_softmac_mac_attach(remotemac->mac_private, athphy);
	athphy->cu_softmac_phy_attach(athphy->phy_private, remotemac);

	/* start receiving data */
	while (connected && old_stop_count == atomic_read(&ktund_stop_count)) {

	    /* check for closed connection */
	    if (sock->sk->sk_state != TCP_ESTABLISHED && sock->sk->sk_state != TCP_CLOSE_WAIT)
		break;

	    /* test for data in the queue */
	    if (!skb_queue_empty(&sock->sk->sk_receive_queue))
		connected = ktund_tunnel_rx(remotemac);
	    else
		interruptible_sleep_on_timeout(&waitq, 1);
	}

	/* disconnected */
	//ath_cu_remote_unregister_rx_func(ath_dev, ktund_tunnel_txskb);
	remotemac->cu_softmac_mac_set_rx_func(remotemac->mac_private, 0, 0);
	remotemac->cu_softmac_mac_detach(remotemac->mac_private);
	athphy->cu_softmac_phy_detach(athphy->phy_private);

	/* decrement reference count */
	//dev_put(ath_dev);
	cu_softmac_phyinfo_free(athphy);
	cu_softmac_macinfo_free(remotemac);

	server_sock = 0;
	sock_release(sock);
	sock = 0;
	connected = 0;
    }

    /* cleanup */
    if (sock) 
	sock_release(sock);

    kfree(rx_buf);

    module_put(THIS_MODULE);
    printk(NAME ": tunnel exiting\n");
    return 0;
}

/* main thread */
static int
ktund_main(void *v)
{
    DECLARE_WAIT_QUEUE_HEAD(waitq);
    
    daemonize(NAME"_main");

    while (ktund_unload == 0) {
	/* wait for activation */
	ktund_start = 0;
	while (ktund_start == 0 && ktund_unload == 0) {
	    interruptible_sleep_on_timeout(&waitq, HZ);
	}
	if (ktund_unload) break;
	
	/* start a tunnel thread */
	(void)kernel_thread(ktund_tunnel_main, NULL, CLONE_KERNEL);
	
	/* wait for deactivation */
	ktund_stop = 0;
	while (ktund_stop == 0 && ktund_unload == 0) {
	    interruptible_sleep_on_timeout(&waitq, HZ);
	}
	/* stop threads */
	atomic_inc(&ktund_stop_count);    
    }

    atomic_inc(&ktund_stop_count);
    module_put(THIS_MODULE);

    printk(NAME ": unloaded\n");
    return 0;
}

extern void ktund_proc_start(void);
extern void ktund_proc_stop(void);

static int __init ktund_init(void)
{
    printk(NAME ": init\n");

    __module_get(THIS_MODULE);

    ktund_start = 0;
    ktund_stop = 1;
    ktund_unload = 0;
 
    atomic_set(&ktund_stop_count, 0);

    sprintf(ktund_server_name, "%s", DEFAULT_SERVER_NAME);
    ktund_server_port = DEFAULT_SERVER_PORT;

    /* enable /proc entries */
    ktund_proc_start();

    /* start the main thread */
    (void)kernel_thread(ktund_main, NULL, CLONE_KERNEL);

    
    return 0;
}

static void __exit ktund_exit(void)
{
    printk(NAME ": exit\n");
    ktund_proc_stop();
}

module_init(ktund_init);
module_exit(ktund_exit);

MODULE_AUTHOR("Jeff Fifield");
MODULE_DESCRIPTION("ktund");
MODULE_LICENSE("GPL");
//EXPORT_SYMBOL( ktund_tunnel_txskb );
//EXPORT_SYMBOL( ktund_tunnel_tx );
