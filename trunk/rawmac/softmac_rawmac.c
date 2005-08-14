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
 * This is the RawMAC 
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
#include "softmac_netif.h"

MODULE_LICENSE("GPL");

/* private instance data */
struct rawmac_instance {
    CU_SOFTMAC_MACLAYER_INFO *macinfo;
    CU_SOFTMAC_MACLAYER_INFO *macinfo_real;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo_fake;

    CU_SOFTMAC_NETIF_HANDLE *netif;
    CU_SOFTMAC_MAC_RX_FUNC netif_rx;
    void *netif_rx_priv;

    int id;
    rwlock_t lock;
};

/* XXX tcpdump/libpcap do not tolerate variable-length headers,
 * yet, so we pad every radiotap header to 64 bytes. Ugh.
 */
#define IEEE80211_RADIOTAP_HDRLEN	64

/* The radio capture header precedes the 802.11 header. */
struct ieee80211_radiotap_header {
	u_int8_t	it_version;	/* Version 0. Only increases
					 * for drastic changes,
					 * introduction of compatible
					 * new fields does not count.
					 */
	u_int8_t	it_pad;
	u_int16_t       it_len;         /* length of the whole
					 * header in bytes, including
					 * it_version, it_pad,
					 * it_len, and data fields.
					 */
	u_int32_t       it_present;     /* A bitmap telling which
					 * fields are present. Set bit 31
					 * (0x80000000) to extend the
					 * bitmap by another 32 bits.
					 * Additional extensions are made
					 * by setting bit 31.
					 */
} __attribute__((__packed__));

/* Name                                 Data type       Units
 * ----                                 ---------       -----
 *
 * IEEE80211_RADIOTAP_TSFT              u_int64_t       microseconds
 *
 *      Value in microseconds of the MAC's 64-bit 802.11 Time
 *      Synchronization Function timer when the first bit of the
 *      MPDU arrived at the MAC. For received frames, only.
 *
 * IEEE80211_RADIOTAP_CHANNEL           2 x u_int16_t   MHz, bitmap
 *
 *      Tx/Rx frequency in MHz, followed by flags (see below).
 *
 * IEEE80211_RADIOTAP_FHSS              u_int16_t       see below
 *
 *      For frequency-hopping radios, the hop set (first byte)
 *      and pattern (second byte).
 *
 * IEEE80211_RADIOTAP_RATE              u_int8_t        500kb/s
 *
 *      Tx/Rx data rate
 *
 * IEEE80211_RADIOTAP_DBM_ANTSIGNAL     int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF signal power at the antenna, decibel difference from
 *      one milliwatt.
 *
 * IEEE80211_RADIOTAP_DBM_ANTNOISE      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      RF noise power at the antenna, decibel difference from one
 *      milliwatt.
 *
 * IEEE80211_RADIOTAP_DB_ANTSIGNAL      u_int8_t        decibel (dB)
 *
 *      RF signal power at the antenna, decibel difference from an
 *      arbitrary, fixed reference.
 *
 * IEEE80211_RADIOTAP_DB_ANTNOISE       u_int8_t        decibel (dB)
 *
 *      RF noise power at the antenna, decibel difference from an
 *      arbitrary, fixed reference point.
 *
 * IEEE80211_RADIOTAP_LOCK_QUALITY      u_int16_t       unitless
 *
 *      Quality of Barker code lock. Unitless. Monotonically
 *      nondecreasing with "better" lock strength. Called "Signal
 *      Quality" in datasheets.  (Is there a standard way to measure
 *      this?)
 *
 * IEEE80211_RADIOTAP_TX_ATTENUATION    u_int16_t       unitless
 *
 *      Transmit power expressed as unitless distance from max
 *      power set at factory calibration.  0 is max power.
 *      Monotonically nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DB_TX_ATTENUATION u_int16_t       decibels (dB)
 *
 *      Transmit power expressed as decibel distance from max power
 *      set at factory calibration.  0 is max power.  Monotonically
 *      nondecreasing with lower power levels.
 *
 * IEEE80211_RADIOTAP_DBM_TX_POWER      int8_t          decibels from
 *                                                      one milliwatt (dBm)
 *
 *      Transmit power expressed as dBm (decibels from a 1 milliwatt
 *      reference). This is the absolute power level measured at
 *      the antenna port.
 *
 * IEEE80211_RADIOTAP_FLAGS             u_int8_t        bitmap
 *
 *      Properties of transmitted and received frames. See flags
 *      defined below.
 *
 * IEEE80211_RADIOTAP_ANTENNA           u_int8_t        antenna index
 *
 *      Unitless indication of the Rx/Tx antenna for this packet.
 *      The first antenna is antenna 0.
 *
 * IEEE80211_RADIOTAP_RX_FLAGS          u_int16_t       bitmap
 *
 *	Properties of received frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_TX_FLAGS          u_int16_t       bitmap
 *
 *	Properties of transmitted frames. See flags defined below.
 *
 * IEEE80211_RADIOTAP_RTS_RETRIES       u_int8_t        data
 *
 *	Number of rts retries a transmitted frame used.
 * 
 * IEEE80211_RADIOTAP_DATA_RETRIES      u_int8_t        data
 *
 *	Number of unicast retries a transmitted frame used.
 * 
 */
enum ieee80211_radiotap_type {
	IEEE80211_RADIOTAP_TSFT = 0,
	IEEE80211_RADIOTAP_FLAGS = 1,
	IEEE80211_RADIOTAP_RATE = 2,
	IEEE80211_RADIOTAP_CHANNEL = 3,
	IEEE80211_RADIOTAP_FHSS = 4,
	IEEE80211_RADIOTAP_DBM_ANTSIGNAL = 5,
	IEEE80211_RADIOTAP_DBM_ANTNOISE = 6,
	IEEE80211_RADIOTAP_LOCK_QUALITY = 7,
	IEEE80211_RADIOTAP_TX_ATTENUATION = 8,
	IEEE80211_RADIOTAP_DB_TX_ATTENUATION = 9,
	IEEE80211_RADIOTAP_DBM_TX_POWER = 10,
	IEEE80211_RADIOTAP_ANTENNA = 11,
	IEEE80211_RADIOTAP_DB_ANTSIGNAL = 12,
	IEEE80211_RADIOTAP_DB_ANTNOISE = 13,
	IEEE80211_RADIOTAP_RX_FLAGS = 14,
	IEEE80211_RADIOTAP_TX_FLAGS = 15,
	IEEE80211_RADIOTAP_RTS_RETRIES = 16,
	IEEE80211_RADIOTAP_DATA_RETRIES = 17,
	IEEE80211_RADIOTAP_EXT = 31
};

/*
 * Radio capture format.
 */
#define ATH_RX_RADIOTAP_PRESENT (		\
	(1 << IEEE80211_RADIOTAP_FLAGS)		| \
	(1 << IEEE80211_RADIOTAP_RATE)		| \
	(1 << IEEE80211_RADIOTAP_CHANNEL)	| \
	(1 << IEEE80211_RADIOTAP_ANTENNA)	| \
	(1 << IEEE80211_RADIOTAP_DB_ANTSIGNAL)	| \
	(1 << IEEE80211_RADIOTAP_RX_FLAGS)	| \
	0)

struct ath_rx_radiotap_header {
	struct ieee80211_radiotap_header wr_ihdr;
	u_int8_t	wr_flags;		/* XXX for padding */
	u_int8_t	wr_rate;
	u_int16_t	wr_chan_freq;
	u_int16_t	wr_chan_flags;
	u_int8_t	wr_antenna;
	u_int8_t	wr_antsignal;
	u_int16_t       wr_rx_flags;
};
#define       IEEE80211_RADIOTAP_F_FCS        0x10/* frame includes FCS */
#define       IEEE80211_RADIOTAP_F_RX_BADFCS  0x0001      /* frame failed crc check */

static int rawmac_next_id;
static const char *rawmac_name = "rawmac";

/**
 * Every SoftMAC MAC or PHY layer provides a CU_SOFTMAC_LAYER_INFO interface
 */
static CU_SOFTMAC_LAYER_INFO the_rawmac;

/* attach to a phy layer */
static int
rawmac_mac_attach(void *me, CU_SOFTMAC_PHYLAYER_INFO *phyinfo)
{
    printk("%s\n", __func__);
    struct rawmac_instance *inst = me;
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
rawmac_mac_detach(void *me)
{
    printk("%s\n", __func__);
    struct rawmac_instance *inst = me;
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
rawmac_mac_set_netif_rx_func(void *me, 
				CU_SOFTMAC_MAC_RX_FUNC rxfunc, 
				void *rxpriv) 
{
    printk("%s\n", __func__);
    struct rawmac_instance *inst = me;
    unsigned long flags;

    write_lock_irqsave(&(inst->lock), flags);

    inst->netif_rx = rxfunc;
    inst->netif_rx_priv = rxpriv;

    write_unlock_irqrestore(&(inst->lock), flags);

    return 0;
}

static int
rawmac_mac_packet_tx(void *me, struct sk_buff *skb, int intop)
{
    printk("%s\n", __func__);
    struct rawmac_instance *inst = me; 

    BUG_ON(intop);

    read_lock(&(inst->lock));

    /* first send it to the encapsulated MAC for processing
     * when finished, the MAC will call rawmac_macdone
     */
    if (inst->macinfo_real) {
	inst->macinfo_real->cu_softmac_mac_packet_tx(inst->macinfo_real->mac_private, skb, intop);
    }

    read_unlock(&(inst->lock));

    return CU_SOFTMAC_MAC_NOTIFY_OK;
}

/* called by mac layer as netif_rx */
static void
rawmac_macdone(void *me, struct sk_buff *skb)
{
    printk("%s\n", __func__);

    struct rawmac_instance *inst = me;
    read_lock(&(inst->lock));

    /* encapsulate with radiotap header */
    struct ath_rx_radiotap_header *th;

    if (skb_headroom(skb) < sizeof(struct ath_rx_radiotap_header) &&
	pskb_expand_head(skb, 
			 sizeof(struct ath_rx_radiotap_header), 
			 0, GFP_ATOMIC)) {
	printk("%s: couldn't pskb_expand_head\n", __func__);
	printk("%s: XXX leak!\n", __func__);
	goto out;
    }
		
    th = (struct ath_rx_radiotap_header *) skb_push(skb, sizeof(struct ath_rx_radiotap_header));
    memset(th, 0, sizeof(struct ath_rx_radiotap_header));
    th->wr_ihdr.it_version = 0;
    th->wr_ihdr.it_len = sizeof(struct ath_rx_radiotap_header);
    th->wr_ihdr.it_present = ATH_RX_RADIOTAP_PRESENT;
    th->wr_flags = IEEE80211_RADIOTAP_F_FCS;
    th->wr_rate = cu_softmac_ath_get_rx_bitrate(inst->phyinfo->phy_private, skb);
    th->wr_chan_freq 
	= ieee80211_ieee2mhz( cu_softmac_ath_get_rx_channel(inst->phyinfo->phy_private, skb) );
    //th->wr_chan_flags = ic->ic_ibss_chan->ic_flags;
    th->wr_antenna =  cu_softmac_ath_get_rx_antenna(inst->phyinfo->phy_private, skb);
    th->wr_antsignal = cu_softmac_ath_get_rx_rssi(inst->phyinfo->phy_private, skb);
    th->wr_rx_flags = 0;
    if (cu_softmac_ath_has_rx_crc_error(inst->phyinfo->phy_private, skb))
	th->wr_rx_flags |= IEEE80211_RADIOTAP_F_RX_BADFCS;

    /* send it up the stack */
    printk("%s %d\n", __func__, skb->len);
    
    inst->netif_rx(inst->netif_rx_priv, skb);
 out:
    read_unlock(&(inst->lock));
}

static int
rawmac_mac_packet_rx(void *me, struct sk_buff *skb, int intop)
{
    //printk("%s\n", __func__);

    struct rawmac_instance *inst = me;

    read_lock(&(inst->lock));

    if (inst->macinfo_real)
	inst->macinfo_real->cu_softmac_mac_packet_rx(inst->macinfo_real->mac_private, skb, intop);
    else if (inst->phyinfo)
	inst->phyinfo->cu_softmac_phy_free_skb(inst->phyinfo->phy_private, skb);
    else
	kfree_skb(skb);

    read_unlock(&(inst->lock));

    return CU_SOFTMAC_MAC_NOTIFY_OK;
} 

static int 
rawmac_netif_txhelper(CU_SOFTMAC_NETIF_HANDLE nif, void* priv, struct sk_buff *skb)
{
    printk("%s\n", __func__);

    struct rawmac_instance *inst = priv;
    if (inst) {
	int ret = rawmac_mac_packet_tx(inst, skb, 0);
	if (ret != CU_SOFTMAC_MAC_TX_OK)
	    dev_kfree_skb(skb);
    }
    return 0;
}

/* create a network interface and attach to it */
static int 
rawmac_create_and_attach_netif(void *me)
{
    struct rawmac_instance *inst = me;
    CU_SOFTMAC_MACLAYER_INFO *macinfo = inst->macinfo;
    int ret = 0;
    struct net_device *checknet = 0;

    checknet = dev_get_by_name(macinfo->name);
    if (checknet) {
	printk("%s: attaching to %s\n", __func__, macinfo->name);
	inst->netif = cu_softmac_netif_from_dev(checknet);
	dev_put(checknet);
	cu_softmac_netif_set_tx_callback(inst->netif, rawmac_netif_txhelper, (void *)inst);
    } else {
	printk("%s: creating %s\n", __func__, macinfo->name);
	inst->netif = cu_softmac_netif_create_eth(macinfo->name, 0, rawmac_netif_txhelper, inst);
    }

    if (inst->netif) {
	rawmac_mac_set_netif_rx_func(inst, cu_softmac_netif_rx_packet, inst->netif);
    } else {
	printk("%s: error unable to attach to netif!\n", __func__);
	ret = -1;
    }
    return ret;
}

static int 
rawmac_fakephy_sendpacket(void *me, int max_inflight, struct sk_buff *skb)
{
    printk("%s\n", __func__);

    struct rawmac_instance *inst = (struct rawmac_instance *)me;
    CU_SOFTMAC_PHYLAYER_INFO *phy;
    int txresult;

    read_lock(&(inst->lock));

    phy = inst->phyinfo;
    if (phy)
	txresult = phy->cu_softmac_phy_sendpacket(phy->phy_private, max_inflight, skb); 

    read_unlock(&(inst->lock));
    return txresult;
}

static struct sk_buff*
rawmac_fakephy_alloc_skb(void *me, int len)
{
    struct rawmac_instance *inst = me;
    CU_SOFTMAC_PHYLAYER_INFO *phy;
    struct sk_buff *skb;

    read_lock(&(inst->lock));

    phy = inst->phyinfo;
    if (phy)
	skb = phy->cu_softmac_phy_alloc_skb(phy->phy_private, len);

    read_unlock(&(inst->lock));
    return skb;
}

/* create and return a new rawmac instance */
static void *
rawmac_new_instance (void *layer_priv)
{
    printk("%s\n", __func__);

    struct rawmac_instance *inst;
    void *ret = 0;

    inst = kmalloc(sizeof(struct rawmac_instance), GFP_ATOMIC);
    if (inst) {
	memset(inst, 0, sizeof(struct rawmac_instance));

	inst->lock = RW_LOCK_UNLOCKED;
	inst->id = rawmac_next_id++;

	/* setup the macinfo structure */
	inst->macinfo = cu_softmac_macinfo_alloc();
	inst->macinfo->mac_private = inst;
	inst->macinfo->layer = &the_rawmac;
	snprintf(inst->macinfo->name, CU_SOFTMAC_NAME_SIZE, "%s%d", the_rawmac.name, inst->id);

	/* override some macinfo functions */
	/* the rest remain pointed at the default "do nothing" functions */
	inst->macinfo->cu_softmac_mac_packet_tx = rawmac_mac_packet_tx;
	inst->macinfo->cu_softmac_mac_packet_rx = rawmac_mac_packet_rx;
	inst->macinfo->cu_softmac_mac_attach = rawmac_mac_attach;
	inst->macinfo->cu_softmac_mac_detach = rawmac_mac_detach;
	inst->macinfo->cu_softmac_mac_set_rx_func = rawmac_mac_set_netif_rx_func;

	/* */
	rawmac_create_and_attach_netif(inst);

	/* */
	inst->phyinfo_fake = cu_softmac_phyinfo_alloc();
	inst->phyinfo_fake->phy_private = inst;
	snprintf(inst->phyinfo_fake->name, 
		 CU_SOFTMAC_NAME_SIZE, 
		 "%s_fake_phy", inst->macinfo->name);
	inst->phyinfo_fake->cu_softmac_phy_sendpacket = rawmac_fakephy_sendpacket;
	inst->phyinfo_fake->cu_softmac_phy_alloc_skb = rawmac_fakephy_alloc_skb;

	/* */
	inst->macinfo_real = cu_softmac_layer_new_instance("athmac");
	if (inst->macinfo_real) {
	    cu_softmac_macinfo_get(inst->macinfo_real);
	    inst->macinfo_real->cu_softmac_mac_set_rx_func(inst->macinfo_real->mac_private,
							   rawmac_macdone,
							   (void *)inst);
	    inst->macinfo_real->cu_softmac_mac_attach(inst->macinfo_real->mac_private,
						      inst->phyinfo_fake);
	} else {
	    printk("%s: error unable to attach to mac\n", __func__);
	}

	/* register with softmac */
	cu_softmac_macinfo_register(inst->macinfo);

	/* we've registered with softmac, decrement the ref count */
	cu_softmac_macinfo_free(inst->macinfo);
	    
	ret = inst->macinfo;
    }
    return ret;
}

/* called by softmac_core when a rawmac CU_SOFTMAC_MACLAYER_INFO
 * instance is deallocated 
 */
static void
rawmac_free_instance (void *layer_priv, void *info)
{
    printk("%s\n", __func__);
    CU_SOFTMAC_MACLAYER_INFO *macinfo = info;
    struct rawmac_instance *inst = macinfo->mac_private;

    if (inst->phyinfo)
	cu_softmac_phyinfo_free(inst->phyinfo);

    /* detach and free phyinfo_fake */
    inst->macinfo_real->cu_softmac_mac_detach(inst->macinfo_real->mac_private);
    if (inst->phyinfo_fake)
	cu_softmac_phyinfo_free(inst->phyinfo_fake);
    kfree(inst);
}

static int __init 
softmac_rawmac_init(void)
{
    printk("%s\n", __func__);
    /* register the rawmac layer with softmac */
    strncpy(the_rawmac.name, rawmac_name, CU_SOFTMAC_NAME_SIZE);
    the_rawmac.cu_softmac_layer_new_instance = rawmac_new_instance;
    the_rawmac.cu_softmac_layer_free_instance = rawmac_free_instance;
    cu_softmac_layer_register(&the_rawmac);

    return 0;
}

static void __exit 
softmac_rawmac_exit(void)
{
    printk("%s\n", __func__);
    /* tell softmac we're leaving */
    cu_softmac_layer_unregister((CU_SOFTMAC_LAYER_INFO *)&the_rawmac);
}

module_init(softmac_rawmac_init);
module_exit(softmac_rawmac_exit);
