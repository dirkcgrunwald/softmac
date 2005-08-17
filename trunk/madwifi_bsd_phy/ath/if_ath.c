/*-
 * Copyright (c) 2002-2005 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * Alternatively, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") version 2 as published by the Free
 * Software Foundation.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 * $Id$
 */

__FBSDID("$FreeBSD: src/sys/dev/ath/if_ath.c,v 1.76 2005/01/24 20:31:24 sam Exp $");

/*
 * Driver for the Atheros Wireless LAN controller.
 *
 * This software is derived from work of Atsushi Onoe; his contribution
 * is greatly appreciated.
 */
#include <linux/config.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/cache.h>
#include <linux/sysctl.h>
#include <linux/proc_fs.h>
#include <linux/if_arp.h>
#ifdef HAS_CU_SOFTMAC
#include <linux/etherdevice.h>
#include "cu_softmac_api.h"
#include "cu_softmac_ath_api.h"
#endif

#include <asm/uaccess.h>

#include "if_ethersubr.h"		/* for ETHER_IS_MULTICAST */
#include "if_media.h"
#include "if_llc.h"

#include <net80211/ieee80211_var.h>

#include "radar.h"

#include "if_athvar.h"
#include "ah_desc.h"
#include "ah_devid.h"			/* XXX to identify IBM cards */
#include "ah.h"

#ifdef ATH_PCI		/* PCI BUS */
#include "if_ath_pci.h"
#endif			/* PCI BUS */
#ifdef ATH_AHB		/* AHB BUS */
#include "if_ath_ahb.h"
#endif			/* AHB BUS */
extern	void bus_read_cachesize(struct ath_softc *sc, u_int8_t *csz);

/* unalligned little endian access */     
#define LE_READ_2(p)							\
	((u_int16_t)							\
	 ((((u_int8_t *)(p))[0]      ) | (((u_int8_t *)(p))[1] <<  8)))
#define LE_READ_4(p)							\
	((u_int32_t)							\
	 ((((u_int8_t *)(p))[0]      ) | (((u_int8_t *)(p))[1] <<  8) |	\
	  (((u_int8_t *)(p))[2] << 16) | (((u_int8_t *)(p))[3] << 24)))

enum {
	ATH_LED_TX,
	ATH_LED_RX,
	ATH_LED_POLL,
};

static int	ath_init(struct net_device *);
static int	ath_reset(struct net_device *);
static void	ath_fatal_tasklet(TQUEUE_ARG);
static void	ath_bstuck_tasklet(TQUEUE_ARG);
static void	ath_rxorn_tasklet(TQUEUE_ARG);
static void	ath_bmiss_tasklet(TQUEUE_ARG);
static void	ath_radar_tasklet(TQUEUE_ARG);
static int	ath_stop_locked(struct net_device *);
static int	ath_stop(struct net_device *);
static int	ath_media_change(struct net_device *);
static void	ath_initkeytable(struct ath_softc *);
static int	ath_key_alloc(struct ieee80211com *,
			const struct ieee80211_key *);
static int	ath_key_delete(struct ieee80211com *,
			const struct ieee80211_key *);
static int	ath_key_set(struct ieee80211com *, const struct ieee80211_key *,
			const u_int8_t mac[IEEE80211_ADDR_LEN]);
static void	ath_key_update_begin(struct ieee80211com *);
static void	ath_key_update_end(struct ieee80211com *);
static void	ath_mode_init(struct net_device *);
static void	ath_setslottime(struct ath_softc *);
static void	ath_updateslot(struct net_device *);
static int	ath_beaconq_setup(struct ath_hal *);
static int	ath_beacon_alloc(struct ath_softc *, struct ieee80211_node *);
static void	ath_beacon_setup(struct ath_softc *, struct ath_buf *);
static void	ath_beacon_tasklet(struct net_device *);
static void	ath_beacon_free(struct ath_softc *);
static void	ath_beacon_config(struct ath_softc *);
static void	ath_descdma_cleanup(struct ath_softc *sc, ath_bufhead *);
static int	ath_desc_alloc(struct ath_softc *);
static void	ath_desc_free(struct ath_softc *);
static struct ieee80211_node *ath_node_alloc(struct ieee80211_node_table *);
static void	ath_node_free(struct ieee80211_node *);
static u_int8_t	ath_node_getrssi(const struct ieee80211_node *);
static int	ath_rxbuf_init(struct ath_softc *, struct ath_buf *);
static void	ath_recv_mgmt(struct ieee80211com *, struct sk_buff *,
			struct ieee80211_node *,
			int subtype, int rssi, u_int32_t rstamp);
static void	ath_setdefantenna(struct ath_softc *, u_int);
static void	ath_rx_tasklet(TQUEUE_ARG data);
static struct ath_txq *ath_txq_setup(struct ath_softc*, int qtype, int subtype);
static int	ath_tx_setup(struct ath_softc *, int, int);
static int	ath_wme_update(struct ieee80211com *);
static void	ath_tx_cleanupq(struct ath_softc *, struct ath_txq *);
static void	ath_tx_cleanup(struct ath_softc *);
static int	ath_start(struct sk_buff *, struct net_device *);
static int	ath_tx_setup(struct ath_softc *, int ac, int txq);
static int	ath_tx_start(struct net_device *, struct ieee80211_node *,
			     struct ath_buf *, struct sk_buff *);
static void	ath_tx_tasklet_q0(TQUEUE_ARG data);
static void	ath_tx_tasklet_q0123(TQUEUE_ARG data);
static void	ath_tx_tasklet(TQUEUE_ARG data);
static void	ath_tx_timeout(struct net_device *);
static int	ath_chan_set(struct ath_softc *, struct ieee80211_channel *);
static void	ath_draintxq(struct ath_softc *);
static void	ath_stoprecv(struct ath_softc *);
static int	ath_startrecv(struct ath_softc *);
static void	ath_chan_change(struct ath_softc *, struct ieee80211_channel *);
static void	ath_next_scan(unsigned long);
static void	ath_calibrate(unsigned long);
static int	ath_newstate(struct ieee80211com *, enum ieee80211_state, int);
#if IEEE80211_VLAN_TAG_USED
static void	ath_vlan_register(struct net_device *, struct vlan_group *);
static void	ath_vlan_kill_vid(struct net_device *, unsigned short );
#endif
static struct net_device_stats *ath_getstats(struct net_device *);
#ifdef CONFIG_NET_WIRELESS
static struct iw_statistics *ath_iw_getstats(struct net_device *);
static struct iw_handler_def ath_iw_handler_def;
#endif
static void	ath_newassoc(struct ieee80211com *,
			struct ieee80211_node *, int);
static int	ath_getchannels(struct net_device *, u_int cc,
			HAL_BOOL outdoor, HAL_BOOL xchanmode);
static void	ath_led_event(struct ath_softc *, int);
static void     ath_led_off(unsigned long arg);
static void	ath_update_txpow(struct ath_softc *);

static int	ath_set_mac_address(struct net_device *, void *);
static int	ath_change_mtu(struct net_device *, int);
static int	ath_ioctl(struct net_device *, struct ifreq *, int);

static int	ath_rate_setup(struct net_device *, u_int mode);
static void	ath_setcurmode(struct ath_softc *, enum ieee80211_phymode);

static int      ath_rawdev_attach(struct ath_softc *);
static void     ath_rawdev_detach(struct ath_softc *);
#ifdef CONFIG_SYSCTL
static void	ath_dynamic_sysctl_register(struct ath_softc *);
static void	ath_dynamic_sysctl_unregister(struct ath_softc *);
#endif /* CONFIG_SYSCTL */
static void	ath_announce(struct ath_softc *);

static const char *hal_status_desc[] = {
	"No error",
	"No hardware present or device not yet supported",
	"Memory allocation failed",
	"Hardware didn't respond as expected",
	"EEPROM magic number invalid",
	"EEPROM version invalid",
	"EEPROM unreadable",
	"EEPROM checksum invalid",
	"EEPROM read problem",
	"EEPROM mac address invalid",
	"EEPROM size not supported",
	"Attempt to change write-locked EEPROM",
	"Invalid parameter to function",
	"Hardware revision not supported",
	"Hardware self-test failed",
	"Operation incomplete"
};

static	int ath_dwelltime = 200;		/* 5 channels/second */
static	int ath_calinterval = 30;		/* calibrate every 30 secs */
static	int ath_countrycode = CTRY_DEFAULT;	/* country code */
static	int ath_regdomain = 0;			/* regulatory domain */
static	int ath_outdoor = AH_TRUE;		/* enable outdoor use */
static	int ath_xchanmode = AH_TRUE;		/* enable extended channels */

//#define AR_DEBUG
#ifdef AR_DEBUG
static	int ath_debug = 0;
#define	IFF_DUMPPKTS(sc, _m) \
	((sc->sc_debug & _m) || ieee80211_msg_dumppkts(&sc->sc_ic))
enum {
	ATH_DEBUG_XMIT		= 0x00000001,	/* basic xmit operation */
	ATH_DEBUG_XMIT_DESC	= 0x00000002,	/* xmit descriptors */
	ATH_DEBUG_RECV		= 0x00000004,	/* basic recv operation */
	ATH_DEBUG_RECV_DESC	= 0x00000008,	/* recv descriptors */
	ATH_DEBUG_RATE		= 0x00000010,	/* rate control */
	ATH_DEBUG_RESET		= 0x00000020,	/* reset processing */
	ATH_DEBUG_MODE		= 0x00000040,	/* mode init/setup */
	ATH_DEBUG_BEACON 	= 0x00000080,	/* beacon handling */
	ATH_DEBUG_WATCHDOG 	= 0x00000100,	/* watchdog timeout */
	ATH_DEBUG_INTR		= 0x00001000,	/* ISR */
	ATH_DEBUG_TX_PROC	= 0x00002000,	/* tx ISR proc */
	ATH_DEBUG_RX_PROC	= 0x00004000,	/* rx ISR proc */
	ATH_DEBUG_BEACON_PROC	= 0x00008000,	/* beacon ISR proc */
	ATH_DEBUG_CALIBRATE	= 0x00010000,	/* periodic calibration */
	ATH_DEBUG_KEYCACHE	= 0x00020000,	/* key cache management */
	ATH_DEBUG_STATE		= 0x00040000,	/* 802.11 state transitions */
	ATH_DEBUG_NODE		= 0x00080000,	/* node management */
	ATH_DEBUG_LED		= 0x00100000,	/* led management */
	ATH_DEBUG_FATAL		= 0x80000000,	/* fatal errors */
	ATH_DEBUG_ANY		= 0xffffffff
};
#define	DPRINTF(sc, _m, _fmt, ...) do {				\
	if (sc->sc_debug & (_m))					\
		printk(_fmt, __VA_ARGS__);			\
} while (0)
#define	KEYPRINTF(sc, ix, hk, mac) do {				\
	if (sc->sc_debug & ATH_DEBUG_KEYCACHE)			\
		ath_keyprint(__func__, ix, hk, mac);		\
} while (0)
static	void ath_printrxbuf(struct ath_buf *bf, int);
static	void ath_printtxbuf(struct ath_buf *bf, int);
#else
#define	IFF_DUMPPKTS(sc, _m)	0
#define	DPRINTF(sc, _m, _fmt, ...)
#define	KEYPRINTF(sc, k, ix, mac)
#endif

static	int countrycode = -1;
static	int outdoor = -1;
static	int xchanmode = -1;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,52))
MODULE_PARM(countrycode, "i");
MODULE_PARM(outdoor, "i");
MODULE_PARM(xchanmode, "i");
#else
module_param(countrycode, int, 0);
module_param(outdoor, int, 0);
module_param(xchanmode, int, 0);
#endif
MODULE_PARM_DESC(countrycode, "Override default country code");
MODULE_PARM_DESC(outdoor, "Enable/disable outdoor use");
MODULE_PARM_DESC(xchanmode, "Enable/disable extended channel mode");


/*
 * For packet capture, define the same physical layer packet header 
 * structure as used in the wlan-ng driver 
 */
enum {
	DIDmsg_lnxind_wlansniffrm		= 0x00000044,
	DIDmsg_lnxind_wlansniffrm_hosttime	= 0x00010044,
	DIDmsg_lnxind_wlansniffrm_mactime	= 0x00020044,
	DIDmsg_lnxind_wlansniffrm_channel	= 0x00030044,
	DIDmsg_lnxind_wlansniffrm_rssi		= 0x00040044,
	DIDmsg_lnxind_wlansniffrm_sq		= 0x00050044,
	DIDmsg_lnxind_wlansniffrm_signal	= 0x00060044,
	DIDmsg_lnxind_wlansniffrm_noise		= 0x00070044,
	DIDmsg_lnxind_wlansniffrm_rate		= 0x00080044,
	DIDmsg_lnxind_wlansniffrm_istx		= 0x00090044,
	DIDmsg_lnxind_wlansniffrm_frmlen	= 0x000A0044
};
enum {
	P80211ENUM_msgitem_status_no_value	= 0x00
};
enum {
	P80211ENUM_truth_false			= 0x00,
	P80211ENUM_truth_true			= 0x01
};

typedef struct {
	u_int32_t did;
	u_int16_t status;
	u_int16_t len;
	u_int32_t data;
} p80211item_uint32_t;

typedef struct {
	u_int32_t msgcode;
	u_int32_t msglen;
#define WLAN_DEVNAMELEN_MAX 16
	u_int8_t devname[WLAN_DEVNAMELEN_MAX];
	p80211item_uint32_t hosttime;
	p80211item_uint32_t mactime;
	p80211item_uint32_t channel;
	p80211item_uint32_t rssi;
	p80211item_uint32_t sq;
	p80211item_uint32_t signal;
	p80211item_uint32_t noise;
	p80211item_uint32_t rate;
	p80211item_uint32_t istx;
	p80211item_uint32_t frmlen;
} wlan_ng_prism2_header;

#ifdef HAS_CU_SOFTMAC

// register with SoftMAC 
static void ath_cu_softmac_register(struct ath_softc* sc);
// unregister from SoftMAC
static void ath_cu_softmac_unregister(struct ath_softc* sc);

// ath_tx_raw_start works like ath_tx_start except it doesn't
// do encapsulation...
static int ath_tx_raw_start(struct net_device *, struct ieee80211_node *,
			    struct ath_buf *, struct sk_buff *);

// ath_cu_softmac_handle_rx,txdone are used to handle packet rx
// or txdone signals, either in the top half (set "intop" to 1)
// or bottom half (set "intop" to 0)
static int ath_cu_softmac_handle_rx(struct net_device* dev,int intop);
static int ath_cu_softmac_handle_txdone(struct net_device* dev, int intop);

// ath_cu_softmac_rx function is called when a packet comes in 
static int ath_cu_softmac_rx(struct net_device*, struct sk_buff*,int intop);

// The ath_cu_softmac_*_tasklet functions are optionally scheduled to
// run as tasklets if there's too much stuff to do right away.
static void ath_cu_softmac_rx_tasklet(TQUEUE_ARG data);
static void ath_cu_softmac_txdone_tasklet(TQUEUE_ARG data);
static void ath_cu_softmac_work_tasklet(TQUEUE_ARG data);
static int ath_cu_softmac_packetduration(struct net_device* dev,struct sk_buff* skb);
// ath_cu_softmac_set_phocus_state directs the state of
// the "phocus" antenna if attached.
void cu_softmac_ath_set_phocus_state(u_int16_t state,int16_t settle);

// Encapsulate/decapsulate the required extra header gunk
static struct sk_buff* ath_cu_softmac_encapsulate(struct ath_softc* sc,struct sk_buff* skb);
//static struct sk_buff* cu_softmac_ath_decapsulate(struct ath_softc* sc,struct sk_buff* skb);
// returns length of header or -1 if unknown packet type
static int ath_cu_softmac_getheaderlen(struct ath_softc*,struct sk_buff*);
// returns CU_SOFTMAC_HEADER_* variable
static int ath_cu_softmac_getheadertype(struct ath_softc*,struct sk_buff*);
static unsigned char ath_cu_softmac_getheadertype_cb(struct ath_softc*,struct sk_buff*);

//static int cu_softmac_ath_issoftmac(struct ath_softc* sc,struct sk_buff* skb);
static unsigned char ath_cu_softmac_tag_cb(struct ath_softc* sc,
					   struct ath_desc* ds,
					   struct sk_buff* skb);
static struct sk_buff * ath_alloc_skb(u_int size, u_int align);

/*
**
** Functions exported via pointers from the CU_SOFTMAC_PHYLAYER_INFO device table.
**
*/
static int cu_softmac_phy_attach_ath(CU_SOFTMAC_PHY_HANDLE nfh,CU_SOFTMAC_MACLAYER_INFO* macinfo);
static void cu_softmac_phy_detach_ath(CU_SOFTMAC_PHY_HANDLE nfh);
static u_int64_t cu_softmac_phy_get_time_ath(CU_SOFTMAC_PHY_HANDLE nfh);
static void cu_softmac_phy_set_time_ath(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t curtime);
static void cu_softmac_phy_schedule_work_asap_ath(CU_SOFTMAC_PHY_HANDLE nfh);
static struct sk_buff* cu_softmac_phy_alloc_skb_ath(CU_SOFTMAC_PHY_HANDLE nfh,int datalen);
static void cu_softmac_phy_free_skb_ath(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);
static int cu_softmac_phy_sendpacket_ath(CU_SOFTMAC_PHY_HANDLE nfh,
					 int max_packets_inflight,
					 struct sk_buff* skb);
static int cu_softmac_phy_sendpacket_keepskbonfail_ath(CU_SOFTMAC_PHY_HANDLE nfh,
						       int max_packets_inflight,
						       struct sk_buff* skb);
static u_int32_t cu_softmac_phy_get_duration_ath(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb);
static u_int32_t cu_softmac_phy_get_txlatency_ath(CU_SOFTMAC_PHY_HANDLE nfh);

static int ath_cu_softmac_athmac_start(struct sk_buff* skb, struct net_device *dev);
static int cu_softmac_mac_packet_tx_ath(void *me, struct sk_buff* skb, int intop);
static int cu_softmac_mac_packet_rx_ath(void *me, struct sk_buff* skb, int intop);

static CU_SOFTMAC_LAYER_INFO the_athmac; // atheros 802.11 mac
static CU_SOFTMAC_LAYER_INFO the_athphy; // atheros softmac phy
/*
** Exported via pointers from the softmac CU_SOFTMAC_LAYER_INFO structure
*/
static void *cu_softmac_layer_new_instance_athphy(void *layer_private);
static void *cu_softmac_layer_new_instance_athmac(void *layer_private);
static void cu_softmac_layer_free_instance_athphy(void *layer_private, void *instance);
static void cu_softmac_layer_free_instance_athmac(void *layer_private, void *instance);

static int ath_cu_softmac_athphy_make_procfs(struct ath_softc *sc);
static int ath_cu_softmac_athphy_delete_procfs(struct ath_softc *sc);
static int ath_cu_softmac_athphy_read_proc(char *page, char **start, off_t off, 
					   int count, int *eof, void *data) ;
static int ath_cu_softmac_athphy_write_proc(struct file *file, const char __user *buffer, 
					    unsigned long count, void *data);
/*
**
** END OF HAS_CU_SOFTMAC CHUNK
**
*/
#endif

int
ath_attach(u_int16_t devid, struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah;
	HAL_STATUS status;
	int error = 0, i;
	u_int8_t csz;

	DPRINTF(sc, ATH_DEBUG_ANY, "%s: devid 0x%x\n", __func__, devid);

	/*
	 * Cache line size is used to size and align various
	 * structures used to communicate with the hardware.
	 */
	bus_read_cachesize(sc, &csz);
	/* XXX assert csz is non-zero */
	sc->sc_cachelsz = csz << 2;		/* convert to bytes */

	ATH_LOCK_INIT(sc);
	ATH_TXBUF_LOCK_INIT(sc);

	ATH_INIT_TQUEUE(&sc->sc_rxtq,	ath_rx_tasklet,		dev);
	ATH_INIT_TQUEUE(&sc->sc_rxorntq,ath_rxorn_tasklet,	dev);
	ATH_INIT_TQUEUE(&sc->sc_fataltq,ath_fatal_tasklet,	dev);
	ATH_INIT_TQUEUE(&sc->sc_bmisstq,ath_bmiss_tasklet,	dev);
	ATH_INIT_TQUEUE(&sc->sc_bstuckq,ath_bstuck_tasklet,	dev);
	ATH_INIT_TQUEUE(&sc->sc_radartq,ath_radar_tasklet,	dev);

#ifdef HAS_CU_SOFTMAC
	/*
	 * softmac specific initialization
	 */
	ATH_INIT_TQUEUE(&sc->sc_cu_softmac_worktq,ath_cu_softmac_work_tasklet,dev);

	atomic_set(&(sc->sc_cu_softmac_tx_packets_inflight),0);
	sc->sc_cu_softmac_mac_lock = RW_LOCK_UNLOCKED;
	sc->sc_cu_softmac_defaultmac = cu_softmac_macinfo_alloc();
	sc->sc_cu_softmac_mac = sc->sc_cu_softmac_defaultmac;
	sc->sc_cu_softmac_phy = 0;
	sc->sc_cu_softmac_txlatency = ATH_CU_SOFTMAC_DEFAULT_TXLATENCY;
	sc->sc_cu_softmac_phocus_settletime = ATH_CU_SOFTMAC_DEFAULT_PHOCUS_SETTLETIME;

	sc->sc_cu_softmac_wifictl0 = CU_SOFTMAC_WIFICTL0;
	sc->sc_cu_softmac_wifictl1 = CU_SOFTMAC_WIFICTL1;

	sc->sc_cu_softmac_mac_inst = kmalloc(sizeof(struct cu_softmac_athmac_instance),GFP_ATOMIC);
	memset(sc->sc_cu_softmac_mac_inst, 0, sizeof(struct cu_softmac_athmac_instance));
	sc->sc_cu_softmac_mac_inst->lock = RW_LOCK_UNLOCKED;
	sc->sc_cu_softmac_mac_inst->defaultphy = cu_softmac_phyinfo_alloc();
	sc->sc_cu_softmac_mac_inst->phyinfo = sc->sc_cu_softmac_mac_inst->defaultphy;

	ath_cu_softmac_register(sc);
#endif

	/*
	 * Attach the hal and verify ABI compatibility by checking
	 * the hal's ABI signature against the one the driver was
	 * compiled with.  A mismatch indicates the driver was
	 * built with an ah.h that does not correspond to the hal
	 * module loaded in the kernel.
	 */
	ah = _ath_hal_attach(devid, sc, 0, (void *) dev->mem_start, &status);
	if (ah == NULL) {
		printk(KERN_ERR "%s: unable to attach hardware: '%s' (HAL status %u)\n",
			__func__, hal_status_desc[status], status);
		error = ENXIO;
		goto bad;
	}
	if (ah->ah_abi != HAL_ABI_VERSION) {
		printk(KERN_ERR "%s: HAL ABI mismatch; "
			"driver expects 0x%x, HAL reports 0x%x\n",
			__func__, HAL_ABI_VERSION, ah->ah_abi);
		error = ENXIO;          /* XXX */
		goto bad;
	}
	sc->sc_ah = ah;

	/*
	 * Check if the MAC has multi-rate retry support.
	 * We do this by trying to setup a fake extended
	 * descriptor.  MAC's that don't have support will
	 * return false w/o doing anything.  MAC's that do
	 * support it will return true w/o doing anything.
	 */
	sc->sc_mrretry = ath_hal_setupxtxdesc(ah, NULL, 0,0, 0,0, 0,0);

	/*
	 * Check if the device has hardware counters for PHY
	 * errors.  If so we need to enable the MIB interrupt
	 * so we can act on stat triggers.
	 */
	if (ath_hal_hwphycounters(ah))
		sc->sc_needmib = 1;

	/*
	 * Get the hardware key cache size.
	 */
	sc->sc_keymax = ath_hal_keycachesize(ah);
	if (sc->sc_keymax > sizeof(sc->sc_keymap) * NBBY) {
		if_printf(dev,
			"Warning, using only %zu of %u key cache slots\n",
			sizeof(sc->sc_keymap) * NBBY, sc->sc_keymax);
		sc->sc_keymax = sizeof(sc->sc_keymap) * NBBY;
	}
	/*
	 * Reset the key cache since some parts do not
	 * reset the contents on initial power up.
	 */
	for (i = 0; i < sc->sc_keymax; i++)
		ath_hal_keyreset(ah, i);
	/*
	 * Mark key cache slots associated with global keys
	 * as in use.  If we knew TKIP was not to be used we
	 * could leave the +32, +64, and +32+64 slots free.
	 * XXX only for splitmic.
	 */
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		setbit(sc->sc_keymap, i);
		setbit(sc->sc_keymap, i+32);
		setbit(sc->sc_keymap, i+64);
		setbit(sc->sc_keymap, i+32+64);
	}

	/*
	 * Collect the channel list using the default country
	 * code and including outdoor channels.  The 802.11 layer
	 * is resposible for filtering this list based on settings
	 * like the phy mode.
	 */
	if (countrycode != -1)
		ath_countrycode = countrycode;
	if (outdoor != -1)
		ath_outdoor = outdoor;
	if (xchanmode != -1)
		ath_xchanmode = xchanmode;
	error = ath_getchannels(dev, ath_countrycode,
			ath_outdoor, ath_xchanmode);
	if (error != 0)
		goto bad;

	/*
	 * Setup rate tables for all potential media types.
	 */
	ath_rate_setup(dev, IEEE80211_MODE_11A);
	ath_rate_setup(dev, IEEE80211_MODE_11B);
	ath_rate_setup(dev, IEEE80211_MODE_11G);
	ath_rate_setup(dev, IEEE80211_MODE_TURBO_A);
	ath_rate_setup(dev, IEEE80211_MODE_TURBO_G);
	/* NB: setup here so ath_rate_update is happy */
	ath_setcurmode(sc, IEEE80211_MODE_11A);

	/*
	 * Allocate tx+rx descriptors and populate the lists.
	 */
	error = ath_desc_alloc(sc);
	if (error != 0) {
		if_printf(dev, "failed to allocate descriptors: %d\n", error);
		goto bad;
	}

	/*
	 * Allocate hardware transmit queues: one queue for
	 * beacon frames and one data queue for each QoS
	 * priority.  Note that the hal handles reseting
	 * these queues at the needed time.
	 *
	 * XXX PS-Poll
	 */
	sc->sc_bhalq = ath_beaconq_setup(ah);
	if (sc->sc_bhalq == (u_int) -1) {
		if_printf(dev, "unable to setup a beacon xmit queue!\n");
		goto bad2;
	}
	sc->sc_cabq = ath_txq_setup(sc, HAL_TX_QUEUE_CAB, 0);
	if (sc->sc_cabq == NULL) {
		if_printf(dev, "unable to setup CAB xmit queue!\n");
		error = EIO;
		goto bad2;
	}
	/* NB: insure BK queue is the lowest priority h/w queue */
	if (!ath_tx_setup(sc, WME_AC_BK, HAL_WME_AC_BK)) {
		if_printf(dev, "unable to setup xmit queue for %s traffic!\n",
			ieee80211_wme_acnames[WME_AC_BK]);
		error = EIO;
		goto bad2;
	}
	if (!ath_tx_setup(sc, WME_AC_BE, HAL_WME_AC_BE) ||
	    !ath_tx_setup(sc, WME_AC_VI, HAL_WME_AC_VI) ||
	    !ath_tx_setup(sc, WME_AC_VO, HAL_WME_AC_VO)) {
		/* 
		 * Not enough hardware tx queues to properly do WME;
		 * just punt and assign them all to the same h/w queue.
		 * We could do a better job of this if, for example,
		 * we allocate queues when we switch from station to
		 * AP mode.
		 */
		if (sc->sc_ac2q[WME_AC_VI] != NULL)
			ath_tx_cleanupq(sc, sc->sc_ac2q[WME_AC_VI]);
		if (sc->sc_ac2q[WME_AC_BE] != NULL)
			ath_tx_cleanupq(sc, sc->sc_ac2q[WME_AC_BE]);
		sc->sc_ac2q[WME_AC_BE] = sc->sc_ac2q[WME_AC_BK];
		sc->sc_ac2q[WME_AC_VI] = sc->sc_ac2q[WME_AC_BK];
		sc->sc_ac2q[WME_AC_VO] = sc->sc_ac2q[WME_AC_BK];
	}

	/* 
	 * Special case certain configurations.  Note the
	 * CAB queue is handled by these specially so don't
	 * include them when checking the txq setup mask.
	 */
	switch (sc->sc_txqsetup &~ (1<<sc->sc_cabq->axq_qnum)) {
	case 0x01:
		ATH_INIT_TQUEUE(&sc->sc_txtq, ath_tx_tasklet_q0, dev);
		break;
	case 0x0f:
		ATH_INIT_TQUEUE(&sc->sc_txtq, ath_tx_tasklet_q0123, dev);
		break;
	default:
		ATH_INIT_TQUEUE(&sc->sc_txtq, ath_tx_tasklet, dev);
		break;
	}

	/*
	 * Setup rate control.  Some rate control modules
	 * call back to change the anntena state so expose
	 * the necessary entry points.
	 * XXX maybe belongs in struct ath_ratectrl?
	 */
	sc->sc_setdefantenna = ath_setdefantenna;
	sc->sc_rc = ath_rate_attach(sc);
	if (sc->sc_rc == NULL) {
		error = EIO;
		goto bad2;
	}

	init_timer(&sc->sc_scan_ch);
	sc->sc_scan_ch.function = ath_next_scan;
	sc->sc_scan_ch.data = (unsigned long) dev;

	init_timer(&sc->sc_cal_ch);
	sc->sc_cal_ch.function = ath_calibrate;
	sc->sc_cal_ch.data = (unsigned long) dev;

	sc->sc_blinking = 0;
	sc->sc_ledstate = 1;
	sc->sc_ledon = 0;			/* low true */
	sc->sc_ledidle = (2700*HZ)/1000;	/* 2.7sec */

	init_timer(&sc->sc_ledtimer);
	sc->sc_ledtimer.function = ath_led_off;
	sc->sc_ledtimer.data = (unsigned long) sc;
	/*
	 * Auto-enable soft led processing for IBM cards and for
	 * 5211 minipci cards.  Users can also manually enable/disable
	 * support with a sysctl.
	 */
	sc->sc_softled = (devid == AR5212_DEVID_IBM || devid == AR5211_DEVID);
	if (sc->sc_softled) {
		ath_hal_gpioCfgOutput(ah, sc->sc_ledpin);
		ath_hal_gpioset(ah, sc->sc_ledpin, !sc->sc_ledon);
	}

	ether_setup(dev);
	dev->open = ath_init;
	dev->stop = ath_stop;
	dev->hard_start_xmit = ath_start;
	dev->tx_timeout = ath_tx_timeout;
	dev->watchdog_timeo = 5 * HZ;			/* XXX */
	dev->set_multicast_list = ath_mode_init;
	dev->do_ioctl = ath_ioctl;
	dev->get_stats = ath_getstats;
	dev->set_mac_address = ath_set_mac_address;
 	dev->change_mtu = &ath_change_mtu;
	dev->tx_queue_len = ATH_TXBUF;			/* TODO? 1 for mgmt frame */
#ifdef CONFIG_NET_WIRELESS
	dev->get_wireless_stats = ath_iw_getstats;
	ieee80211_ioctl_iwsetup(&ath_iw_handler_def);
	dev->wireless_handlers = &ath_iw_handler_def;
#endif /* CONFIG_NET_WIRELESS */
#if IEEE80211_VLAN_TAG_USED
	dev->features |= NETIF_F_HW_VLAN_TX | NETIF_F_HW_VLAN_RX;
	dev->vlan_rx_register = ath_vlan_register;
	dev->vlan_rx_kill_vid = ath_vlan_kill_vid;
#endif /* IEEE80211_VLAN_TAG_USED */

	ic->ic_dev = dev;
	ic->ic_devstats = &sc->sc_devstats;
	ic->ic_init = ath_init;
	ic->ic_reset = ath_reset;
	ic->ic_newassoc = ath_newassoc;
	ic->ic_updateslot = ath_updateslot;
	ic->ic_wme.wme_update = ath_wme_update;
	/* XXX not right but it's not used anywhere important */
	ic->ic_phytype = IEEE80211_T_OFDM;
	ic->ic_opmode = IEEE80211_M_STA;
	ic->ic_caps =
		  IEEE80211_C_IBSS		/* ibss, nee adhoc, mode */
		| IEEE80211_C_HOSTAP		/* hostap mode */
		| IEEE80211_C_MONITOR		/* monitor mode */
		| IEEE80211_C_SHPREAMBLE	/* short preamble supported */
		| IEEE80211_C_SHSLOT		/* short slot time supported */
		| IEEE80211_C_WPA		/* capable of WPA1+WPA2 */
		;

	/*
	 * initialize management queue
	 */
	skb_queue_head_init(&ic->ic_mgtq);

	/*
	 * Query the hal to figure out h/w crypto support.
	 */
	if (ath_hal_ciphersupported(ah, HAL_CIPHER_WEP))
		ic->ic_caps |= IEEE80211_C_WEP;
	if (ath_hal_ciphersupported(ah, HAL_CIPHER_AES_OCB))
		ic->ic_caps |= IEEE80211_C_AES;
	if (ath_hal_ciphersupported(ah, HAL_CIPHER_AES_CCM))
		ic->ic_caps |= IEEE80211_C_AES_CCM;
	if (ath_hal_ciphersupported(ah, HAL_CIPHER_CKIP))
		ic->ic_caps |= IEEE80211_C_CKIP;
	if (ath_hal_ciphersupported(ah, HAL_CIPHER_TKIP)) {
		ic->ic_caps |= IEEE80211_C_TKIP;
		/*
		 * Check if h/w does the MIC and/or whether the
		 * separate key cache entries are required to
		 * handle both tx+rx MIC keys.
		 */
		if (ath_hal_ciphersupported(ah, HAL_CIPHER_MIC))
			ic->ic_caps |= IEEE80211_C_TKIPMIC;
		if (ath_hal_tkipsplit(ah))
			sc->sc_splitmic = 1;
	}
	/*
	 * TPC support can be done either with a global cap or
	 * per-packet support.  The latter is not available on
	 * all parts.  We're a bit pedantic here as all parts
	 * support a global cap.
	 */
	sc->sc_hastpc = ath_hal_hastpc(ah);
	if (sc->sc_hastpc || ath_hal_hastxpowlimit(ah))
		ic->ic_caps |= IEEE80211_C_TXPMGT;

	/*
	 * Mark WME capability only if we have sufficient
	 * hardware queues to do proper priority scheduling.
	 */
	if (sc->sc_ac2q[WME_AC_BE] != sc->sc_ac2q[WME_AC_BK])
		ic->ic_caps |= IEEE80211_C_WME;
	/*
	 * Check for frame bursting capability.
	 */
	if (ath_hal_hasbursting(ah))
		ic->ic_caps |= IEEE80211_C_BURST;

	/*
	 * Indicate we need the 802.11 header padded to a
	 * 32-bit boundary for 4-address and QoS frames.
	 */
	ic->ic_flags |= IEEE80211_F_DATAPAD;

	/*
	 * Query the hal about antenna support.
	 */
	if (ath_hal_hasdiversity(ah)) {
		sc->sc_hasdiversity = 1;
		sc->sc_diversity = ath_hal_getdiversity(ah);
	}
	sc->sc_defant = ath_hal_getdefantenna(ah);

	/*
	 * Not all chips have the VEOL support we want to
	 * use with IBSS beacons; check here for it.
	 */
	sc->sc_hasveol = ath_hal_hasveol(ah);

	sc->sc_rxfilter = 0;
	sc->sc_rawdev_enabled = 0;
	sc->sc_rawdev.type = ARPHRD_IEEE80211;

	/* get mac address from hardware */
	ath_hal_getmac(ah, ic->ic_myaddr);
	IEEE80211_ADDR_COPY(dev->dev_addr, ic->ic_myaddr);

	/* call MI attach routine. */
	ieee80211_ifattach(ic);
	/* override default methods */
	ic->ic_node_alloc = ath_node_alloc;
	sc->sc_node_free = ic->ic_node_free;
	ic->ic_node_free = ath_node_free;
	ic->ic_node_getrssi = ath_node_getrssi;
	sc->sc_recv_mgmt = ic->ic_recv_mgmt;
	ic->ic_recv_mgmt = ath_recv_mgmt;
	sc->sc_newstate = ic->ic_newstate;
	ic->ic_newstate = ath_newstate;
	ic->ic_crypto.cs_key_alloc = ath_key_alloc;
	ic->ic_crypto.cs_key_delete = ath_key_delete;
	ic->ic_crypto.cs_key_set = ath_key_set;
	ic->ic_crypto.cs_key_update_begin = ath_key_update_begin;
	ic->ic_crypto.cs_key_update_end = ath_key_update_end;

	radar_init(ic);

	/* complete initialization */
	ieee80211_media_init(ic, ath_media_change, ieee80211_media_status);

	if (register_netdev(dev)) {
		printk(KERN_ERR "%s: unable to register device\n", dev->name);
		goto bad3;
	}

	/*
	 * Attach dynamic MIB vars and announce support
	 * now that we have a device name with unit number.
	 */
#ifdef CONFIG_SYSCTL
	ath_dynamic_sysctl_register(sc);
	ath_rate_dynamic_sysctl_register(sc);
	ieee80211_sysctl_register(ic);
#endif /* CONFIG_SYSCTL */
	ieee80211_announce(ic);
	ath_announce(sc);
	return 0;
bad3:
	ieee80211_ifdetach(ic);
	ath_rate_detach(sc->sc_rc);
bad2:
	if (sc->sc_txq[WME_AC_BK].axq_qnum != (u_int) -1) {
		ATH_TXQ_LOCK_DESTROY(&sc->sc_txq[WME_AC_BK]);
	}
	if (sc->sc_txq[WME_AC_BE].axq_qnum != (u_int) -1) {
		ATH_TXQ_LOCK_DESTROY(&sc->sc_txq[WME_AC_BE]);
	}
	if (sc->sc_txq[WME_AC_VI].axq_qnum != (u_int) -1) {
		ATH_TXQ_LOCK_DESTROY(&sc->sc_txq[WME_AC_VI]);
	}
	if (sc->sc_txq[WME_AC_VO].axq_qnum != (u_int) -1) {
		ATH_TXQ_LOCK_DESTROY(&sc->sc_txq[WME_AC_VO]);
	}
	ath_tx_cleanup(sc);
	ath_desc_free(sc);
bad:
	if (ah) {
		ath_hal_detach(ah);
	}
	sc->sc_invalid = 1;
	return error;
}

int
ath_detach(struct net_device *dev)
{
        struct ath_softc *sc = dev->priv;
        struct ieee80211com *ic = &sc->sc_ic;
    
	DPRINTF(sc, ATH_DEBUG_ANY, "%s: flags %x\n", __func__, dev->flags);
	ath_stop(dev);
	sc->sc_invalid = 1;
	/* 
	 * NB: the order of these is important:
	 * o call the 802.11 layer before detaching the hal to
	 *   insure callbacks into the driver to delete global
	 *   key cache entries can be handled
	 * o reclaim the tx queue data structures after calling
	 *   the 802.11 layer as we'll get called back to reclaim
	 *   node state and potentially want to use them
	 * o to cleanup the tx queues the hal is called, so detach
	 *   it last
	 * Other than that, it's straightforward...
	 */
	ieee80211_ifdetach(ic);
	ath_rate_detach(sc->sc_rc);
	ath_desc_free(sc);
	ath_tx_cleanup(sc);
	ath_hal_detach(sc->sc_ah);

#ifdef HAS_CU_SOFTMAC
	ath_cu_softmac_unregister(sc);

	cu_softmac_macinfo_free(sc->sc_cu_softmac_defaultmac);
	sc->sc_cu_softmac_defaultmac = 0;

	cu_softmac_phyinfo_free(sc->sc_cu_softmac_mac_inst->defaultphy);
	sc->sc_cu_softmac_mac_inst->defaultphy = 0;
	kfree(sc->sc_cu_softmac_mac_inst);
	sc->sc_cu_softmac_mac_inst = 0;
#endif

	/*
	 * NB: can't reclaim these until after ieee80211_ifdetach
	 * returns because we'll get called back to reclaim node
	 * state and potentially want to use them.
	 */
#ifdef CONFIG_SYSCTL
	ath_dynamic_sysctl_unregister(sc);
#endif /* CONFIG_SYSCTL */
	ath_rawdev_detach(sc);
	unregister_netdev(dev);
	return 0;
}

void
ath_suspend(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;

	DPRINTF(sc, ATH_DEBUG_ANY, "%s: flags %x\n", __func__, dev->flags);
	if (sc->sc_softled) 
	    	ath_hal_gpioset(ah, sc->sc_ledpin, 1);

	ath_stop(dev);
}

void
ath_resume(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;

	DPRINTF(sc, ATH_DEBUG_ANY, "%s: flags %x\n", __func__, dev->flags);
	ath_init(dev);
	if (sc->sc_softled) {
	    	ath_hal_gpioCfgOutput(ah, sc->sc_ledpin);
	    	ath_hal_gpioset(ah, sc->sc_ledpin, 0);
	}
}

void
ath_shutdown(struct net_device *dev)
{
#ifdef AR_DEBUG
	struct ath_softc *sc = dev->priv;
#endif

	DPRINTF(sc, ATH_DEBUG_ANY, "%s: flags %x\n", __func__, dev->flags);

	ath_stop(dev);
}

/*
 * Interrupt handler.  Most of the actual processing is deferred.
 */
irqreturn_t
ath_intr(int irq, void *dev_id, struct pt_regs *regs)
{
	struct net_device *dev = dev_id;
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;
	HAL_INT status;
	int needmark;

	if (sc->sc_invalid) {
		/*
		 * The hardware is not ready/present, don't touch anything.
		 * Note this can happen early on if the IRQ is shared.
		 */
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: invalid; ignored\n", __func__);
		return IRQ_NONE;
	}
	if (!ath_hal_intrpend(ah))		/* shared irq, not for us */
		return IRQ_NONE;
	if ((dev->flags & (IFF_RUNNING|IFF_UP)) != (IFF_RUNNING|IFF_UP)) {
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: if_flags 0x%x\n",
			__func__, dev->flags);
		ath_hal_getisr(ah, &status);	/* clear ISR */
		ath_hal_intrset(ah, 0);		/* disable further intr's */
		return IRQ_HANDLED;
	}
	needmark = 0;
	/*
	 * Figure out the reason(s) for the interrupt.  Note
	 * that the hal returns a pseudo-ISR that may include
	 * bits we haven't explicitly enabled so we mask the
	 * value to insure we only process bits we requested.
	 */
	ath_hal_getisr(ah, &status);		/* NB: clears ISR too */
	DPRINTF(sc, ATH_DEBUG_INTR, "%s: status 0x%x\n", __func__, status);
	status &= sc->sc_imask;			/* discard unasked for bits */
	if (status & HAL_INT_FATAL) {
		/*
		 * Fatal errors are unrecoverable.  Typically
		 * these are caused by DMA errors.  Unfortunately
		 * the exact reason is not (presently) returned
		 * by the hal.
		 */
		sc->sc_stats.ast_hardware++;
		ath_hal_intrset(ah, 0);		/* disable intr's until reset */
		ATH_SCHEDULE_TQUEUE(&sc->sc_fataltq, &needmark);
	} else if (status & HAL_INT_RXORN) {
		sc->sc_stats.ast_rxorn++;
		ath_hal_intrset(ah, 0);		/* disable intr's until reset */
		ATH_SCHEDULE_TQUEUE(&sc->sc_rxorntq, &needmark);
	} else {
		if (status & HAL_INT_SWBA) {
			/*
			 * Software beacon alert--time to send a beacon.
			 * Handle beacon transmission directly; deferring
			 * this is too slow to meet timing constraints
			 * under load.
			 */
			ath_beacon_tasklet(dev);
		}
		if (status & HAL_INT_RXEOL) {
			/*
			 * NB: the hardware should re-read the link when
			 *     RXE bit is written, but it doesn't work at
			 *     least on older hardware revs.
			 */
			sc->sc_stats.ast_rxeol++;
			sc->sc_rxlink = NULL;
		}
		if (status & HAL_INT_TXURN) {
			sc->sc_stats.ast_txurn++;
			/* bump tx trigger level */
			ath_hal_updatetxtriglevel(ah, AH_TRUE);
		}
		if (status & HAL_INT_RX)
#ifdef HAS_CU_SOFTMAC
		  {
		    if ((sc->sc_cu_softmac) &&
			/*(sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR) &&*/
			!((sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_DEFER_ALL_RX))) {
		      if (ath_cu_softmac_handle_rx(dev,1)) {
			ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq,&needmark);
		      }
		    }
		    else {
		      ATH_SCHEDULE_TQUEUE(&sc->sc_rxtq, &needmark);
		    }
		  }
#else
			ATH_SCHEDULE_TQUEUE(&sc->sc_rxtq, &needmark);
#endif
		if (status & HAL_INT_TX)
#ifdef HAS_CU_SOFTMAC
		  {
		    if ((sc->sc_cu_softmac) &&
			/*(sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR) &&*/
			!(sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_DEFER_ALL_TXDONE)) {
		      if (ath_cu_softmac_handle_txdone(dev,1)) {
			ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq, &needmark);
		      }
		    }
		    else {
		      ATH_SCHEDULE_TQUEUE(&sc->sc_txtq, &needmark);
		    }
		  }
#else
			ATH_SCHEDULE_TQUEUE(&sc->sc_txtq, &needmark);
#endif
		if (status & HAL_INT_BMISS) {
			sc->sc_stats.ast_bmiss++;
			ATH_SCHEDULE_TQUEUE(&sc->sc_bmisstq, &needmark);
		}
		if (status & HAL_INT_MIB) {
			sc->sc_stats.ast_mib++;
			/*
			 * Disable interrupts until we service the MIB
			 * interrupt; otherwise it will continue to fire.
			 */
			ath_hal_intrset(ah, 0);
			/*
			 * Let the hal handle the event.  We assume it will
			 * clear whatever condition caused the interrupt.
			 */
			ath_hal_mibevent(ah,
				&ATH_NODE(sc->sc_ic.ic_bss)->an_halstats);
			ath_hal_intrset(ah, sc->sc_imask);
		}
	}
	if (needmark) {
	    mark_bh(IMMEDIATE_BH);
	}
	return IRQ_HANDLED;
}

static void
ath_fatal_tasklet(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;

	if_printf(dev, "hardware error; resetting\n");
	ath_reset(dev);
}

static void
ath_radar_tasklet (TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_channel *c;

	c = radar_handle_interference (ic);

	if (c == NULL)
	{
 		ath_stop (dev);
		printk ("%s: FATAL ERROR - All available channels are marked as being interfered by radar. Stopping radio.\n", dev->name);
		return;
	}

	ic->ic_des_chan = c;
	ic->ic_ibss_chan = c;
	ieee80211_new_state (ic, IEEE80211_S_INIT, -1);
	ath_init (dev);
}

static void
ath_rxorn_tasklet(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;

	if_printf(dev, "rx FIFO overrun; resetting\n");
	ath_reset(dev);
}

static void
ath_bmiss_tasklet(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

	DPRINTF(sc, ATH_DEBUG_ANY, "%s\n", __func__);
	KASSERT(ic->ic_opmode == IEEE80211_M_STA,
		("unexpect operating mode %u", ic->ic_opmode));
	if (ic->ic_state == IEEE80211_S_RUN) {
		/*
		 * Rather than go directly to scan state, try to
		 * reassociate first.  If that fails then the state
		 * machine will drop us into scanning after timing
		 * out waiting for a probe response.
		 */
		ieee80211_new_state(ic, IEEE80211_S_ASSOC, -1);
	}
}

static u_int
ath_chan2flags(struct ieee80211com *ic, struct ieee80211_channel *chan)
{
#define	N(a)	(sizeof(a) / sizeof(a[0]))
	static const u_int modeflags[] = {
		0,			/* IEEE80211_MODE_AUTO */
		CHANNEL_A,		/* IEEE80211_MODE_11A */
		CHANNEL_B,		/* IEEE80211_MODE_11B */
		CHANNEL_PUREG,		/* IEEE80211_MODE_11G */
		0,			/* IEEE80211_MODE_FH */
		CHANNEL_T,		/* IEEE80211_MODE_TURBO_A */
		CHANNEL_108G		/* IEEE80211_MODE_TURBO_G */
	};
	enum ieee80211_phymode mode = ieee80211_chan2mode(ic, chan);

	KASSERT(mode < N(modeflags), ("unexpected phy mode %u", mode));
	KASSERT(modeflags[mode] != 0, ("mode %u undefined", mode));
	return modeflags[mode];
#undef N
}

static int
ath_init(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	struct ath_hal *ah = sc->sc_ah;
	HAL_STATUS status;
	int error = 0;

	ATH_LOCK(sc);

	DPRINTF(sc, ATH_DEBUG_RESET, "%s: mode %d\n", __func__, ic->ic_opmode);

	/*
	 * Stop anything previously setup.  This is safe
	 * whether this is the first time through or not.
	 */
	ath_stop_locked(dev);

	/*
	 * Change our interface type if we are in monitor mode.
	 */
	dev->type = (ic->ic_opmode == IEEE80211_M_MONITOR) ?
		ARPHRD_IEEE80211_PRISM : ARPHRD_ETHER;

	/*
	 * The basic interface to setting the hardware in a good
	 * state is ``reset''.  On return the hardware is known to
	 * be powered up and with interrupts disabled.  This must
	 * be followed by initialization of the appropriate bits
	 * and then setup of the interrupt mask.
	 */
	sc->sc_curchan.channel = ic->ic_ibss_chan->ic_freq;
	sc->sc_curchan.channelFlags = ath_chan2flags(ic, ic->ic_ibss_chan);
#ifdef HAS_CU_SOFTMAC
	if (!ath_hal_reset(ah, IEEE80211_M_MONITOR, &sc->sc_curchan, AH_FALSE, &status)) {
#else	   
	if (!ath_hal_reset(ah, ic->ic_opmode, &sc->sc_curchan, AH_FALSE, &status)) {
#endif
		if_printf(dev, "unable to reset hardware; hal status %u\n",
			status);
		error = -EIO;
		goto done;
	}

	/*
	 * This is needed only to setup initial state
	 * but it's best done after a reset.
	 */
	ath_update_txpow(sc);

	/*
	 * Setup the hardware after reset: the key cache
	 * is filled as needed and the receive engine is
	 * set going.  Frame transmit is handled entirely
	 * in the frame output path; there's nothing to do
	 * here except setup the interrupt mask.
	 */
	ath_initkeytable(sc);		/* XXX still needed? */
	if (ath_startrecv(sc) != 0) {
		if_printf(dev, "unable to start recv logic\n");
		error = -EIO;
		goto done;
	}

	/*
	 * Enable interrupts.
	 */
	sc->sc_imask = HAL_INT_RX | HAL_INT_TX
		  | HAL_INT_RXEOL | HAL_INT_RXORN
		  | HAL_INT_FATAL | HAL_INT_GLOBAL;	// TODO: compiler warning integer overflow in expression
	/*
	 * Enable MIB interrupts when there are hardware phy counters.
	 * Note we only do this (at the moment) for station mode.
	 */
	if (sc->sc_needmib && ic->ic_opmode == IEEE80211_M_STA)
		sc->sc_imask |= HAL_INT_MIB;
	ath_hal_intrset(ah, sc->sc_imask);

	dev->flags |= IFF_RUNNING;
	ic->ic_state = IEEE80211_S_INIT;

	/*
	 * The hardware should be ready to go now so it's safe
	 * to kick the 802.11 state machine as it's likely to
	 * immediately call back to us to send mgmt frames.
	 */
	ni = ic->ic_bss;
	ni->ni_chan = ic->ic_ibss_chan;
	ath_chan_change(sc, ni->ni_chan);
	if (ic->ic_opmode != IEEE80211_M_MONITOR) {
		if (ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
			ieee80211_new_state(ic, IEEE80211_S_SCAN, -1);
	} else
		ieee80211_new_state(ic, IEEE80211_S_RUN, -1);
done:
	ATH_UNLOCK(sc);
	return error;
}

static int
ath_stop_locked(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;

	DPRINTF(sc, ATH_DEBUG_RESET, "%s: invalid %u flags 0x%x\n",
		__func__, sc->sc_invalid, dev->flags);

	ATH_LOCK_ASSERT(sc);
	if (dev->flags & IFF_RUNNING) {
		/*
		 * Shutdown the hardware and driver:
		 *    reset 802.11 state machine
		 *    stop output from above
		 *    disable interrupts
		 *    turn off timers
		 *    turn off the radio
		 *    clear transmit machinery
		 *    clear receive machinery
		 *    drain and release tx queues
		 *    reclaim beacon resources
		 *    power down hardware
		 *
		 * Note that some of this work is not possible if the
		 * hardware is gone (invalid).
		 */
		ieee80211_new_state(ic, IEEE80211_S_INIT, -1);
		netif_stop_queue(dev);
		if (sc->sc_rawdev_enabled) 
			netif_stop_queue(&sc->sc_rawdev);

		dev->flags &= ~IFF_RUNNING;
		if (!sc->sc_invalid) {
			if (sc->sc_softled) {
				del_timer(&sc->sc_ledtimer);
				ath_hal_gpioset(ah, sc->sc_ledpin,
					!sc->sc_ledon);
				sc->sc_blinking = 0;
			}
			ath_hal_intrset(ah, 0);
		}
		ath_draintxq(sc);
		if (!sc->sc_invalid) {
			ath_stoprecv(sc);
			ath_hal_phydisable(ah);
		} else
			sc->sc_rxlink = NULL;
		ath_beacon_free(sc);
	}
	return 0;
}

/*
 * Stop the device, grabbing the top-level lock to protect
 * against concurrent entry through ath_init (which can happen
 * if another thread does a system call and the thread doing the
 * stop is preempted).
 */
static int
ath_stop(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	int error;

	ATH_LOCK(sc);
	error = ath_stop_locked(dev);
	if (error == 0 && !sc->sc_invalid) {
		/*
		 * Set the chip in full sleep mode.  Note that we are
		 * careful to do this only when bringing the interface
		 * completely to a stop.  When the chip is in this state
		 * it must be carefully woken up or references to
		 * registers in the PCI clock domain may freeze the bus
		 * (and system).  This varies by chip and is mostly an
		 * issue with newer parts that go to sleep more quickly.
		 */
		ath_hal_setpower(sc->sc_ah, HAL_PM_FULL_SLEEP, 0);
	}
	ATH_UNLOCK(sc);
	return error;
}

/*
 * Reset the hardware w/o losing operational state.  This is
 * basically a more efficient way of doing ath_stop, ath_init,
 * followed by state transitions to the current 802.11
 * operational state.  Used to recover from various errors and
 * to reset or reload hardware state.
 */
static int
ath_reset(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211_channel *c;
	HAL_STATUS status;

	if_printf(dev, "resetting\n");
	
	/*
	 * Convert to a HAL channel description with the flags
	 * constrained to reflect the current operating mode.
	 */
	c = ic->ic_ibss_chan;
	sc->sc_curchan.channel = c->ic_freq;
	sc->sc_curchan.channelFlags = ath_chan2flags(ic, c);

	ath_hal_intrset(ah, 0);		/* disable interrupts */
	ath_draintxq(sc);		/* stop xmit side */
	ath_stoprecv(sc);		/* stop recv side */
	/* NB: indicate channel change so we do a full reset */
#ifdef HAS_CU_SOFTMAC
	if (!ath_hal_reset(ah, IEEE80211_M_MONITOR, &sc->sc_curchan, AH_TRUE, &status))
#else
	if (!ath_hal_reset(ah, ic->ic_opmode, &sc->sc_curchan, AH_TRUE, &status))
#endif
		if_printf(dev, "%s: unable to reset hardware: '%s' (%u)\n",
			__func__, hal_status_desc[status], status);
	ath_update_txpow(sc);		/* update tx power state */
	if (ath_startrecv(sc) != 0)	/* restart recv */
		if_printf(dev, "%s: unable to start recv logic\n", __func__);
	/*
	 * We may be doing a reset in response to an ioctl
	 * that changes the channel so update any state that
	 * might change as a result.
	 */
	ath_chan_change(sc, c);
	if (ic->ic_state == IEEE80211_S_RUN)
		ath_beacon_config(sc);	/* restart beacons */
	ath_hal_intrset(ah, sc->sc_imask);

	if (ic->ic_state == IEEE80211_S_RUN)
		netif_wake_queue(dev);	/* restart xmit */

	if (sc->sc_rawdev_enabled)
		netif_wake_queue(&sc->sc_rawdev);
	return 0;
}


#define NUM_RADIOTAP_ELEMENTS 18

static int radiotap_elem_to_bytes[NUM_RADIOTAP_ELEMENTS] = 
	{8, /* IEEE80211_RADIOTAP_TSFT */
	 1, /* IEEE80211_RADIOTAP_FLAGS */
	 1, /* IEEE80211_RADIOTAP_RATE */
	 4, /* IEEE80211_RADIOTAP_CHANNEL */
	 2, /* IEEE80211_RADIOTAP_FHSS */
	 1, /* IEEE80211_RADIOTAP_DBM_ANTSIGNAL */
	 1, /* IEEE80211_RADIOTAP_DBM_ANTNOISE */
	 2, /* IEEE80211_RADIOTAP_LOCK_QUALITY */
	 2, /* IEEE80211_RADIOTAP_TX_ATTENUATION */
	 2, /* IEEE80211_RADIOTAP_DB_TX_ATTENUATION */
	 1, /* IEEE80211_RADIOTAP_DBM_TX_POWER */
	 1, /* IEEE80211_RADIOTAP_ANTENNA */
	 1, /* IEEE80211_RADIOTAP_DB_ANTSIGNAL */
	 1, /* IEEE80211_RADIOTAP_DB_ANTNOISE */
	 2, /* IEEE80211_RADIOTAP_RX_FLAGS */
	 2, /* IEEE80211_RADIOTAP_TX_FLAGS */
	 1, /* IEEE80211_RADIOTAP_RTS_RETRIES */
	 1, /* IEEE80211_RADIOTAP_DATA_RETRIES */
	};


/*
 * the following rt_* functions deal with verifying that a valid
 * radiotap header is on a packet as well as functions to extracting
 * what information is included.
 * XXX maybe these should go in ieee_radiotap.c
 */
static int rt_el_present(struct ieee80211_radiotap_header *th, u_int32_t element)
{
	if (element > NUM_RADIOTAP_ELEMENTS)
		return 0;
	return th->it_present & (1 << element);
}

static int rt_check_header(struct ieee80211_radiotap_header *th, int len) 
{
	int bytes = 0;
	int x = 0;
	if (th->it_version != 0) 
		return 0;

	if (th->it_len < sizeof(struct ieee80211_radiotap_header))
		return 0;
	
	for (x = 0; x < NUM_RADIOTAP_ELEMENTS; x++) {
		if (rt_el_present(th, x))
		    bytes += radiotap_elem_to_bytes[x];
	}

	if (th->it_len < sizeof(struct ieee80211_radiotap_header) + bytes) 
		return 0;
	
	if (th->it_len > len)
		return 0;

	return 1;
}

static u_int8_t *rt_el_offset(struct ieee80211_radiotap_header *th, u_int32_t element) {
	unsigned int x = 0;
	u_int8_t *offset = ((u_int8_t *) th) + sizeof(struct ieee80211_radiotap_header);
	for (x = 0; x < NUM_RADIOTAP_ELEMENTS && x < element; x++) {
		if (rt_el_present(th, x))
			offset += radiotap_elem_to_bytes[x];
	}

	return offset;
}
/*
 * ath_start for raw 802.11 packets.
 */
static int
ath_start_raw(struct sk_buff *skb, struct net_device *dev)
{
#define	CTS_DURATION \
	ath_hal_computetxtime(ah, rt, IEEE80211_ACK_LEN, cix, AH_TRUE)
#define	updateCTSForBursting(_ah, _ds, _txq) \
	ath_hal_updateCTSForBursting(_ah, _ds, \
	    _txq->axq_linkbuf != NULL ? _txq->axq_linkbuf->bf_desc : NULL, \
	    _txq->axq_lastdsWithCTS, _txq->axq_gatingds, \
	    txopLimit, CTS_DURATION)
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	const struct chanAccParams *cap = &ic->ic_wme.wme_chanParams;
	struct ath_txq *txq;
	struct ath_buf *bf;
	HAL_PKT_TYPE atype;
	int pktlen, hdrlen, try0, pri, dot11Rate, txpower; 
	u_int8_t ctsrate, ctsduration, txrate;
	u_int8_t cix = 0xff;         /* NB: silence compiler */
	u_int flags = 0;
	struct ieee80211_frame *wh; 
	struct ath_desc *ds;
	const HAL_RATE_TABLE *rt;

#ifdef HAS_CU_SOFTMAC
	// Keep packets out of the device if it isn't up OR it's
	// been appropriated by the SoftMAC
	if ((sc->sc_dev.flags & IFF_RUNNING) == 0 || sc->sc_invalid ||
	    sc->sc_cu_softmac) {
#else
	if ((sc->sc_dev.flags & IFF_RUNNING) == 0 || sc->sc_invalid) {
#endif
		/* device is not up... silently discard packet */
		dev_kfree_skb(skb);
		return 0;
	}

	/*
	 * Grab a TX buffer and associated resources.
	 */
	ATH_TXBUF_LOCK_BH(sc);
	bf = STAILQ_FIRST(&sc->sc_txbuf);
	if (bf != NULL)
		STAILQ_REMOVE_HEAD(&sc->sc_txbuf, bf_list);
	/* XXX use a counter and leave at least one for mgmt frames */
	if (STAILQ_EMPTY(&sc->sc_txbuf)) {
		DPRINTF(sc, ATH_DEBUG_XMIT, "%s: stop queue\n", __func__);
		sc->sc_stats.ast_tx_qstop++;
		netif_stop_queue(&sc->sc_dev);
		netif_stop_queue(&sc->sc_rawdev);
	}
	ATH_TXBUF_UNLOCK_BH(sc);
	
	if (bf == NULL) {		/* NB: should not happen */
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: out of xmit buffers\n",
			__func__);
		sc->sc_stats.ast_tx_nobuf++;
		dev_kfree_skb(skb);
		return 0;
	}

	rt = sc->sc_currates;
	KASSERT(rt != NULL, ("no rate table, mode %u", sc->sc_curmode));
	flags = HAL_TXDESC_INTREQ | HAL_TXDESC_CLRDMASK;
	try0 = ATH_TXMAXTRY;
	dot11Rate = 0;
	ctsrate = 0;
	ctsduration = 0;
	pri = 0;
	txpower = 60;
	txq = sc->sc_ac2q[pri];
	txrate = rt->info[0].rateCode;
	atype =  HAL_PKT_TYPE_NORMAL;

	/*
	 * strip any physical layer header off the skb, if it is
	 * present, and read out any settings we can, like what txrate
	 * to send this packet at.
	 */
	switch(dev->type) {
	case ARPHRD_IEEE80211:
		break;
	case ARPHRD_IEEE80211_PRISM: {
		wlan_ng_prism2_header *ph = NULL;
		ph = (wlan_ng_prism2_header *) skb->data;
		/* does it look like there is a prism header here? */
		if (skb->len > sizeof (wlan_ng_prism2_header) &&
		    ph->msgcode == DIDmsg_lnxind_wlansniffrm &&
		    ph->rate.did == DIDmsg_lnxind_wlansniffrm_rate) {
			dot11Rate = ph->rate.data;
			skb_pull(skb, sizeof(wlan_ng_prism2_header));
		} 
		break;
	}
	case ARPHRD_IEEE80211_RADIOTAP: {
		struct ieee80211_radiotap_header *th = (struct ieee80211_radiotap_header *) skb->data;
		if (rt_check_header(th, skb->len)) {
			if (rt_el_present(th, IEEE80211_RADIOTAP_RATE)) {
				dot11Rate = *((u_int8_t *) rt_el_offset(th, 
					      IEEE80211_RADIOTAP_RATE));
			}
			if (rt_el_present(th, IEEE80211_RADIOTAP_DATA_RETRIES)) {
				try0 = 1 + *((u_int8_t *) rt_el_offset(th, 
					      IEEE80211_RADIOTAP_DATA_RETRIES));
			}
			if (rt_el_present(th, IEEE80211_RADIOTAP_DBM_TX_POWER)) {
				txpower = *((u_int8_t *) rt_el_offset(th, 
					      IEEE80211_RADIOTAP_DBM_TX_POWER));
				if (txpower > 60) 
					txpower = 60;
				
			}

			skb_pull(skb, th->it_len);
		}
		break;
	}
	default:
		/* nothing */
		break;
	}
	
	if (dot11Rate != 0) {
		int index = sc->sc_rixmap[dot11Rate & IEEE80211_RATE_VAL];
		if (index >= 0 && index < rt->rateCount) {
			txrate = rt->info[index].rateCode;
		}
	}

	wh = (struct ieee80211_frame *) skb->data;
	pktlen = skb->len + IEEE80211_CRC_LEN;
	hdrlen = sizeof(struct ieee80211_frame);

	if (hdrlen < pktlen) 
		hdrlen = pktlen;

	if (IEEE80211_IS_MULTICAST(wh->i_addr1)) {
		flags |= HAL_TXDESC_NOACK;	/* no ack on broad/multicast */
		sc->sc_stats.ast_tx_noack++;
	}
	
	if (IFF_DUMPPKTS(sc, ATH_DEBUG_XMIT))
		ieee80211_dump_pkt(skb->data, skb->len,
				   sc->sc_hwmap[txrate].ieeerate, -1);

	/*
	 * Load the DMA map so any coalescing is done.  This
	 * also calculates the number of descriptors we need.
	 */
	bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
		skb->data, pktlen, BUS_DMA_TODEVICE);
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: skb %p [data %p len %u] skbaddr %lx\n",
		__func__, skb, skb->data, skb->len, (long unsigned int) bf->bf_skbaddr);
	if (BUS_DMA_MAP_ERROR(bf->bf_skbaddr)) {
		if_printf(dev, "%s: DMA mapping failed\n", __func__);
		dev_kfree_skb(skb);
		bf->bf_skb = NULL;
		sc->sc_stats.ast_tx_busdma++;

		ATH_TXBUF_LOCK_BH(sc);
		STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
		ATH_TXBUF_UNLOCK_BH(sc);
		return -EIO;
	}
	bf->bf_skb = skb;
	bf->bf_node = NULL;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = sc->sc_currates;
	KASSERT(rt != NULL, ("no rate table, mode %u", sc->sc_curmode));

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	/* XXX check return value? */
	ath_hal_setuptxdesc(ah, ds
		, pktlen		/* packet length */
		, hdrlen		/* header length */
		, atype			/* Atheros packet type */
		, txpower     	        /* txpower */
		, txrate, try0		/* series 0 rate/tries */
		, HAL_TXKEYIX_INVALID	/* key cache index */
		, sc->sc_txantenna	/* antenna mode */
		, flags			/* flags */
		, ctsrate		/* rts/cts rate */
		, ctsduration		/* rts/cts duration */
	);

	/*
	 * Fillin the remainder of the descriptor info.
	 */
	ds->ds_link = 0;
	ds->ds_data = bf->bf_skbaddr;
	ath_hal_filltxdesc(ah, ds
		, skb->len		/* segment length */
		, AH_TRUE		/* first segment */
		, AH_TRUE		/* last segment */
		, ds			/* first descriptor */
	);

	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: Q%d: %08x %08x %08x %08x %08x %08x\n",
	    __func__, txq->axq_qnum, ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1, ds->ds_hw[0], ds->ds_hw[1]);
	/*
	 * Insert the frame on the outbound list and
	 * pass it on to the hardware.
	 */
	ATH_TXQ_LOCK_BH(txq);
	if (flags & (HAL_TXDESC_RTSENA | HAL_TXDESC_CTSENA)) {
		u_int32_t txopLimit = IEEE80211_TXOP_TO_US(
			cap->cap_wmeParams[pri].wmep_txopLimit);
		/*
		 * When bursting, potentially extend the CTS duration
		 * of a previously queued frame to cover this frame
		 * and not exceed the txopLimit.  If that can be done
		 * then disable RTS/CTS on this frame since it's now
		 * covered (burst extension).  Otherwise we must terminate
		 * the burst before this frame goes out so as not to
		 * violate the WME parameters.  All this is complicated
		 * as we need to update the state of packets on the
		 * (live) hardware queue.  The logic is buried in the hal
		 * because it's highly chip-specific.
		 */
		if (txopLimit != 0) {
			sc->sc_stats.ast_tx_ctsburst++;
			if (updateCTSForBursting(ah, ds, txq) == 0) {
				/*
				 * This frame was not covered by RTS/CTS from
				 * the previous frame in the burst; update the
				 * descriptor pointers so this frame is now
				 * treated as the last frame for extending a
				 * burst.
				 */
				txq->axq_lastdsWithCTS = ds;
				/* set gating Desc to final desc */
				txq->axq_gatingds =
					(struct ath_desc *)txq->axq_link;
			} else
				sc->sc_stats.ast_tx_ctsext++;
		}
	}
	ATH_TXQ_INSERT_TAIL(txq, bf, bf_list);
	DPRINTF(sc, ATH_DEBUG_TX_PROC, "%s: txq depth = %d\n",
		__func__, txq->axq_depth);
	if (txq->axq_link == NULL) {
		ath_hal_puttxbuf(ah, txq->axq_qnum, bf->bf_daddr);
		DPRINTF(sc, ATH_DEBUG_XMIT,
			"%s: TXDP[%u] = %p (%p) depth %d\n", __func__,
			txq->axq_qnum, (caddr_t)bf->bf_daddr, bf->bf_desc,
			txq->axq_depth);
	} else {
		*txq->axq_link = bf->bf_daddr;
		DPRINTF(sc, ATH_DEBUG_XMIT,
			"%s: link[%u](%p)=%p (%p) depth %d\n", __func__,
			txq->axq_qnum, txq->axq_link,
			(caddr_t)bf->bf_daddr, bf->bf_desc, txq->axq_depth);
	}
	txq->axq_link = &bf->bf_desc->ds_link;
	/*
	 * The CAB queue is started from the SWBA handler since
	 * frames only go out on DTIM and to avoid possible races.
	 */
	if (txq != sc->sc_cabq)
		ath_hal_txstart(ah, txq->axq_qnum);
	ATH_TXQ_UNLOCK_BH(txq);

	sc->sc_devstats.tx_packets++;
	sc->sc_devstats.tx_bytes += skb->len;
	sc->sc_dev.trans_start = jiffies;
	sc->sc_rawdev.trans_start = jiffies;

	return 0;
#undef updateCTSForBursting
#undef CTS_DURATION
}

static int
ath_start(struct sk_buff *skb, struct net_device *dev)
{
#define CLEANUP()	\
	do{ \
		ATH_TXBUF_LOCK_BH(sc); \
		STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list); \
		ATH_TXBUF_UNLOCK_BH(sc); \
		if (ni != NULL)	\
			ieee80211_free_node(ni);	\
	} while (0)

	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni;
	struct ath_buf *bf;
	struct ieee80211_cb *cb;
	struct sk_buff *skb0;
	struct ieee80211_frame *wh;
	struct ether_header *eh;
	
	int ret = 0;
	int counter = 0;

	if ((dev->flags & IFF_RUNNING) == 0 || sc->sc_invalid) {

		DPRINTF(sc, ATH_DEBUG_XMIT,
			"%s: discard, invalid %d flags %x\n",
			__func__, sc->sc_invalid, dev->flags);
		sc->sc_stats.ast_tx_invalid++;
		return -ENETDOWN;
	}
#if 0
#ifdef HAS_CU_SOFTMAC
	else if (sc->sc_cu_softmac) {
	  // Keep packets out of the device when in softmac mode
	  dev_kfree_skb_any(skb);
	  return 0;
	}

#endif	
#endif
	for (;;) {
		/*
		 * Grab a TX buffer and associated resources.
		 */
		ATH_TXBUF_LOCK_BH(sc);
		bf = STAILQ_FIRST(&sc->sc_txbuf);
		if (bf != NULL)
			STAILQ_REMOVE_HEAD(&sc->sc_txbuf, bf_list);
		/* XXX use a counter and leave at least one for mgmt frames */
		if (STAILQ_EMPTY(&sc->sc_txbuf)) {
			DPRINTF(sc, ATH_DEBUG_XMIT, "%s: stop queue\n", __func__);
			sc->sc_stats.ast_tx_qstop++;
			netif_stop_queue(dev);
			if (sc->sc_rawdev_enabled)
				netif_stop_queue(&sc->sc_rawdev);
		}
		ATH_TXBUF_UNLOCK_BH(sc);

		if (bf == NULL) {		/* NB: should not happen */
			DPRINTF(sc, ATH_DEBUG_ANY, "%s: out of xmit buffers\n",
				__func__);
			sc->sc_stats.ast_tx_nobuf++;
			break;
		}

		/*
		 * Poll the management queue for frames; they
		 * have priority over normal data frames.
		 */
		IF_DEQUEUE(&ic->ic_mgtq, skb0);
		if (skb0 == NULL) {
			if (counter++ > 200)
			    DPRINTF(sc, ATH_DEBUG_FATAL, "%s (%s): endlessloop (data) (counter=%i)\n", __func__, dev->name, counter);

			if (!skb) {		/* NB: no data (called for mgmt) */
				ATH_TXBUF_LOCK_BH(sc);
				STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
				ATH_TXBUF_UNLOCK_BH(sc);
				break;
			}
			/*
			 * No data frames go out unless we're associated; this
			 * should not happen as the 802.11 layer does not enable
			 * the xmit queue until we enter the RUN state.
			 */
			if (ic->ic_state != IEEE80211_S_RUN) {
				DPRINTF(sc, ATH_DEBUG_ANY,
					"%s: ignore data packet, state %u\n",
					__func__, ic->ic_state);
				sc->sc_stats.ast_tx_discard++;
				ATH_TXBUF_LOCK_BH(sc);
				STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
				ATH_TXBUF_UNLOCK_BH(sc);
				break;
			}
			/* 
			 * Find the node for the destination so we can do
			 * things like power save and fast frames aggregation.
			 */
			if (skb->len < sizeof(struct ether_header)) {
				ic->ic_stats.is_tx_nobuf++;   /* XXX */
				ni = NULL;

				ret = 0; /* error return */
				CLEANUP();
				break;
			}
			eh = (struct ether_header *)skb->data;
			ni = ieee80211_find_txnode(ic, eh->ether_dhost);
			if (ni == NULL) {
				/* NB: ieee80211_find_txnode does stat+msg */

				ret = 0; /* error return */
				CLEANUP();
				break;
			}
			cb = (struct ieee80211_cb *)skb->cb;
			if ((ni->ni_flags & IEEE80211_NODE_PWR_MGT) &&
			    (cb->flags & M_PWR_SAV) == 0) {
				/*
				 * Station in power save mode; pass the frame
				 * to the 802.11 layer and continue.  We'll get
				 * the frame back when the time is right.
				 */
				ieee80211_pwrsave(ic, ni, skb);
				/* don't free this on function exit point */
				skb = NULL;
				CLEANUP();
				break;
			}
			/* calculate priority so we can find the tx queue */
			if (ieee80211_classify(ic, skb, ni)) {
				DPRINTF(sc, ATH_DEBUG_XMIT,
					"%s: discard, classification failure\n",
					__func__);

				ret = 0; /* error return */
				CLEANUP();
				break;
			}
			sc->sc_devstats.tx_packets++;
			sc->sc_devstats.tx_bytes += skb->len;

			/*
			 * Encapsulate the packet for transmission.
			 */
			skb = ieee80211_encap(ic, skb, ni);
			if (skb == NULL) {
				DPRINTF(sc, ATH_DEBUG_ANY,
					"%s: encapsulation failure\n",
					__func__);
				sc->sc_stats.ast_tx_encap++;

				ret = 0; /* error return */
				CLEANUP();
				break;
			}
			/*
			 * using unified sk_buff for transmit data and management frames
			 */
			skb0 = skb;
		} else {
			cb = (struct ieee80211_cb *)skb0->cb;
			ni = cb->ni;

			if (counter++ > 200)
			    DPRINTF(sc, ATH_DEBUG_FATAL, "%s (%s): endlessloop (mgnt) (counter=%i)\n", __func__, dev->name, counter);

			wh = (struct ieee80211_frame *) skb0->data;
			if ((wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == 
				IEEE80211_FC0_SUBTYPE_PROBE_RESP) {
				/* fill time stamp */
				u_int64_t tsf;
				u_int32_t *tstamp;

				tsf = ath_hal_gettsf64(ah);
				/* XXX: adjust 100us delay to xmit */
				tsf += 100;
				tstamp = (u_int32_t *)&wh[1];
				tstamp[0] = htole32(tsf & 0xffffffff);
				tstamp[1] = htole32(tsf >> 32);
			}
			sc->sc_stats.ast_tx_mgmt++;
		}

		if (ath_tx_start(dev, ni, bf, skb0)) {
		        printk("%s error: ath_tx_start failed\n", __func__);
			ret = 0; 	/* TODO: error value */
			skb = NULL;	/* ath_tx_start() already freed this */
			CLEANUP();
			continue;
		}
		/*
		 * the data frame is last
		 */
		if (skb0 == skb) {
			skb = NULL;	/* will be released by tx_processq */
			break; 
		}
		sc->sc_tx_timer = 5;
		mod_timer(&ic->ic_slowtimo, jiffies + HZ);
	}
	if (skb)
		dev_kfree_skb(skb);
	return ret;	/* NB: return !0 only in a ``hard error condition'' */
#undef CLEANUP
}

static int
ath_media_change(struct net_device *dev)
{
#define	IS_UP(dev) \
	((dev->flags & (IFF_RUNNING|IFF_UP)) == (IFF_RUNNING|IFF_UP))
	int error;

	error = ieee80211_media_change(dev);
	if (error == ENETRESET) {
		if (IS_UP(dev))
			error = ath_init(dev);
		else
			error = 0;
	}
	return error;
#undef IS_UP
}

#ifdef AR_DEBUG
static void
ath_keyprint(const char *tag, u_int ix,
	const HAL_KEYVAL *hk, const u_int8_t mac[IEEE80211_ADDR_LEN])
{
	static const char *ciphers[] = {
		"WEP",
		"AES-OCB",
		"AES-CCM",
		"CKIP",
		"TKIP",
		"CLR",
	};
	int i, n;

	printk("%s: [%02u] %-7s ", tag, ix, ciphers[hk->kv_type]);
	for (i = 0, n = hk->kv_len; i < n; i++)
		printk("%02x", hk->kv_val[i]);
	printk(" mac %s", ether_sprintf(mac));
	if (hk->kv_type == HAL_CIPHER_TKIP) {
		printk(" mic ");
		for (i = 0; i < sizeof(hk->kv_mic); i++)
			printk("%02x", hk->kv_mic[i]);
	}
	printk("\n");
}
#endif

/*
 * Set a TKIP key into the hardware.  This handles the
 * potential distribution of key state to multiple key
 * cache slots for TKIP.
 */
static int
ath_keyset_tkip(struct ath_softc *sc, const struct ieee80211_key *k,
	HAL_KEYVAL *hk, const u_int8_t mac[IEEE80211_ADDR_LEN])
{
#define	IEEE80211_KEY_XR	(IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV)
	static const u_int8_t zerobssid[IEEE80211_ADDR_LEN];
	struct ath_hal *ah = sc->sc_ah;

	KASSERT(k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP,
		("got a non-TKIP key, cipher %u", k->wk_cipher->ic_cipher));
	KASSERT(sc->sc_splitmic, ("key cache !split"));
	if ((k->wk_flags & IEEE80211_KEY_XR) == IEEE80211_KEY_XR) {
		/*
		 * TX key goes at first index, RX key at +32.
		 * The hal handles the MIC keys at index+64.
		 */
		memcpy(hk->kv_mic, k->wk_txmic, sizeof(hk->kv_mic));
		KEYPRINTF(sc, k->wk_keyix, hk, zerobssid);
		if (!ath_hal_keyset(ah, k->wk_keyix, hk, zerobssid))
			return 0;

		memcpy(hk->kv_mic, k->wk_rxmic, sizeof(hk->kv_mic));
		KEYPRINTF(sc, k->wk_keyix+32, hk, mac);
		/* XXX delete tx key on failure? */
		return ath_hal_keyset(ah, k->wk_keyix+32, hk, mac);
	} else if (k->wk_flags & IEEE80211_KEY_XR) {
		/*
		 * TX/RX key goes at first index.
		 * The hal handles the MIC keys are index+64.
		 */
		KASSERT(k->wk_keyix < IEEE80211_WEP_NKID,
			("group key at index %u", k->wk_keyix));
		memcpy(hk->kv_mic, k->wk_flags & IEEE80211_KEY_XMIT ?
			k->wk_txmic : k->wk_rxmic, sizeof(hk->kv_mic));
		KEYPRINTF(sc, k->wk_keyix, hk, zerobssid);
		return ath_hal_keyset(ah, k->wk_keyix, hk, zerobssid);
	}
	/* XXX key w/o xmit/recv; need this for compression? */
	return 0;
#undef IEEE80211_KEY_XR
}

/*
 * Set a net80211 key into the hardware.  This handles the
 * potential distribution of key state to multiple key
 * cache slots for TKIP with hardware MIC support.
 */
static int
ath_keyset(struct ath_softc *sc, const struct ieee80211_key *k,
	const u_int8_t mac[IEEE80211_ADDR_LEN])
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	static const u_int8_t ciphermap[] = {
		HAL_CIPHER_WEP,		/* IEEE80211_CIPHER_WEP */
		HAL_CIPHER_TKIP,	/* IEEE80211_CIPHER_TKIP */
		HAL_CIPHER_AES_OCB,	/* IEEE80211_CIPHER_AES_OCB */
		HAL_CIPHER_AES_CCM,	/* IEEE80211_CIPHER_AES_CCM */
		(u_int8_t) -1,		/* 4 is not allocated */
		HAL_CIPHER_CKIP,	/* IEEE80211_CIPHER_CKIP */
		HAL_CIPHER_CLR,		/* IEEE80211_CIPHER_NONE */
	};
	struct ath_hal *ah = sc->sc_ah;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	HAL_KEYVAL hk;

	memset(&hk, 0, sizeof(hk));
	/*
	 * Software crypto uses a "clear key" so non-crypto
	 * state kept in the key cache are maintained and
	 * so that rx frames have an entry to match.
	 */
	if ((k->wk_flags & IEEE80211_KEY_SWCRYPT) == 0) {
		KASSERT(cip->ic_cipher < N(ciphermap),
			("invalid cipher type %u", cip->ic_cipher));
		hk.kv_type = ciphermap[cip->ic_cipher];
		hk.kv_len = k->wk_keylen;
		memcpy(hk.kv_val, k->wk_key, k->wk_keylen);
	} else
		hk.kv_type = HAL_CIPHER_CLR;

	if (hk.kv_type == HAL_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 &&
	    sc->sc_splitmic) {
		return ath_keyset_tkip(sc, k, &hk, mac);
	} else {
		KEYPRINTF(sc, k->wk_keyix, &hk, mac);
		return ath_hal_keyset(ah, k->wk_keyix, &hk, mac);
	}
#undef N
}

/*
 * Fill the hardware key cache with key entries.
 */
static void
ath_initkeytable(struct ath_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct net_device *dev = ic->ic_dev;
	struct ath_hal *ah = sc->sc_ah;
	const u_int8_t *bssid;
	int i;

	/* XXX maybe should reset all keys when !PRIVACY */
	if (ic->ic_state == IEEE80211_S_SCAN)
		bssid = dev->broadcast;
	else
		bssid = ic->ic_bss->ni_bssid;
	for (i = 0; i < IEEE80211_WEP_NKID; i++) {
		struct ieee80211_key *k = &ic->ic_nw_keys[i];

		if (k->wk_keylen == 0) {
			ath_hal_keyreset(ah, i);
			DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s: reset key %u\n",
				__func__, i);
		} else {
			ath_keyset(sc, k, bssid);
		}
	}
}

/*
 * Allocate tx/rx key slots for TKIP.  We allocate two slots for
 * each key, one for decrypt/encrypt and the other for the MIC.
 */
static u_int16_t
key_alloc_2pair(struct ath_softc *sc)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	u_int i, keyix;

	KASSERT(sc->sc_splitmic, ("key cache !split"));
	/* XXX could optimize */
	for (i = 0; i < N(sc->sc_keymap)/4; i++) {
		u_int8_t b = sc->sc_keymap[i];
		if (b != 0xff) {
			/*
			 * One or more slots in this byte are free.
			 */
			keyix = i*NBBY;
			while (b & 1) {
		again:
				keyix++;
				b >>= 1;
			}
			/* XXX IEEE80211_KEY_XMIT | IEEE80211_KEY_RECV */
			if (isset(sc->sc_keymap, keyix+32) ||
			    isset(sc->sc_keymap, keyix+64) ||
			    isset(sc->sc_keymap, keyix+32+64)) {
				/* full pair unavailable */
				/* XXX statistic */
				if (keyix == (i+1)*NBBY) {
					/* no slots were appropriate, advance */
					continue;
				}
				goto again;
			}
			setbit(sc->sc_keymap, keyix);
			setbit(sc->sc_keymap, keyix+64);
			setbit(sc->sc_keymap, keyix+32);
			setbit(sc->sc_keymap, keyix+32+64);
			DPRINTF(sc, ATH_DEBUG_KEYCACHE,
				"%s: key pair %u,%u %u,%u\n",
				__func__, keyix, keyix+64,
				keyix+32, keyix+32+64);
			return keyix;
		}
	}
	DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s: out of pair space\n", __func__);
	return IEEE80211_KEYIX_NONE;
#undef N
}

/*
 * Allocate a single key cache slot.
 */
static u_int16_t
key_alloc_single(struct ath_softc *sc)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	u_int i, keyix;

	/* XXX try i,i+32,i+64,i+32+64 to minimize key pair conflicts */
	for (i = 0; i < N(sc->sc_keymap); i++) {
		u_int8_t b = sc->sc_keymap[i];
		if (b != 0xff) {
			/*
			 * One or more slots are free.
			 */
			keyix = i*NBBY;
			while (b & 1)
				keyix++, b >>= 1;
			setbit(sc->sc_keymap, keyix);
			DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s: key %u\n",
				__func__, keyix);
			return keyix;
		}
	}
	DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s: out of space\n", __func__);
	return IEEE80211_KEYIX_NONE;
#undef N
}

/*
 * Allocate one or more key cache slots for a uniacst key.  The
 * key itself is needed only to identify the cipher.  For hardware
 * TKIP with split cipher+MIC keys we allocate two key cache slot
 * pairs so that we can setup separate TX and RX MIC keys.  Note
 * that the MIC key for a TKIP key at slot i is assumed by the
 * hardware to be at slot i+64.  This limits TKIP keys to the first
 * 64 entries.
 */
static int
ath_key_alloc(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;

	/*
	 * Group key allocation must be handled specially for
	 * parts that do not support multicast key cache search
	 * functionality.  For those parts the key id must match
	 * the h/w key index so lookups find the right key.  On
	 * parts w/ the key search facility we install the sender's
	 * mac address (with the high bit set) and let the hardware
	 * find the key w/o using the key id.  This is preferred as
	 * it permits us to support multiple users for adhoc and/or
	 * multi-station operation.
	 */
	if ((k->wk_flags & IEEE80211_KEY_GROUP) && !sc->sc_mcastkey) {
		u_int keyix;

		if (!(&ic->ic_nw_keys[0] <= k &&
		      k < &ic->ic_nw_keys[IEEE80211_WEP_NKID])) {
			/* should not happen */
			DPRINTF(sc, ATH_DEBUG_KEYCACHE,
				"%s: bogus group key\n", __func__);
			return IEEE80211_KEYIX_NONE;
		}
		keyix = k - ic->ic_nw_keys;
		/*
		 * XXX we pre-allocate the global keys so
		 * have no way to check if they've already been allocated.
		 */
		return keyix;
	}

	/*
	 * We allocate two pair for TKIP when using the h/w to do
	 * the MIC.  For everything else, including software crypto,
	 * we allocate a single entry.  Note that s/w crypto requires
	 * a pass-through slot on the 5211 and 5212.  The 5210 does
	 * not support pass-through cache entries and we map all
	 * those requests to slot 0.
	 */
	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		return key_alloc_single(sc);
	} else if (k->wk_cipher->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 && sc->sc_splitmic) {
		return key_alloc_2pair(sc);
	} else {
		return key_alloc_single(sc);
	}
}

/*
 * Delete an entry in the key cache allocated by ath_key_alloc.
 */
static int
ath_key_delete(struct ieee80211com *ic, const struct ieee80211_key *k)
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;
	const struct ieee80211_cipher *cip = k->wk_cipher;
	u_int keyix = k->wk_keyix;

	DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s: delete key %u\n", __func__, keyix);

	ath_hal_keyreset(ah, keyix);
	/*
	 * Handle split tx/rx keying required for TKIP with h/w MIC.
	 */
	if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
	    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 && sc->sc_splitmic)
		ath_hal_keyreset(ah, keyix+32);		/* RX key */
	if (keyix >= IEEE80211_WEP_NKID) {
		/*
		 * Don't touch keymap entries for global keys so
		 * they are never considered for dynamic allocation.
		 */
		clrbit(sc->sc_keymap, keyix);
		if (cip->ic_cipher == IEEE80211_CIPHER_TKIP &&
		    (k->wk_flags & IEEE80211_KEY_SWMIC) == 0 &&
		    sc->sc_splitmic) {
			clrbit(sc->sc_keymap, keyix+64);	/* TX key MIC */
			clrbit(sc->sc_keymap, keyix+32);	/* RX key */
			clrbit(sc->sc_keymap, keyix+32+64);	/* RX key MIC */
		}
	}
	return 1;
}

/*
 * Set the key cache contents for the specified key.  Key cache
 * slot(s) must already have been allocated by ath_key_alloc.
 */
static int
ath_key_set(struct ieee80211com *ic, const struct ieee80211_key *k,
	const u_int8_t mac[IEEE80211_ADDR_LEN])
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;

	return ath_keyset(sc, k, mac);
}

/*
 * Block/unblock tx+rx processing while a key change is done.
 * We assume the caller serializes key management operations
 * so we only need to worry about synchronization with other
 * uses that originate in the driver.
 */
static void
ath_key_update_begin(struct ieee80211com *ic)
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;
	
	DPRINTF(sc, ATH_DEBUG_FATAL, "%lu %s (%s)\n", jiffies, __func__, dev->name);
	DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s:\n", __func__);
	/*
	 * When called from the rx tasklet we cannot use
	 * tasklet_disable because it will block waiting
	 * for us to complete execution.
	 *
	 * XXX Using in_softirq is not right since we might
	 * be called from other soft irq contexts than
	 * ath_rx_tasklet.
	 * TODO: can cause bugs
	 */
#if 1
	if (!in_softirq())
		tasklet_disable(&sc->sc_rxtq);
#endif
	netif_stop_queue(dev);	// TODO: find a way to not block mgmt frames
	if (sc->sc_rawdev_enabled) 
		netif_stop_queue(&sc->sc_rawdev);
}

static void
ath_key_update_end(struct ieee80211com *ic)
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;

	DPRINTF(sc, ATH_DEBUG_FATAL, "%lu %s (%s)\n", jiffies, __func__, dev->name);
	DPRINTF(sc, ATH_DEBUG_KEYCACHE, "%s:\n", __func__);
	netif_start_queue(dev);
	if (sc->sc_rawdev_enabled) 
		netif_start_queue(&sc->sc_rawdev);
#if 1
	if (!in_softirq())		/* NB: see above */
		tasklet_enable(&sc->sc_rxtq);
#endif
}

/*
 * Calculate the receive filter according to the
 * operating mode and state:
 *
 * o always accept unicast, broadcast, and multicast traffic
 * o maintain current state of phy error reception (the hal
 *   may enable phy error frames for noise immunity work)
 * o probe request frames are accepted only when operating in
 *   hostap, adhoc, or monitor modes
 * o enable promiscuous mode according to the interface state
 * o accept beacons:
 *   - when operating in adhoc mode so the 802.11 layer creates
 *     node table entries for peers,
 *   - when operating in station mode for collecting rssi data when
 *     the station is otherwise quiet, or
 *   - when scanning
 * o accept any additional packets specified by sc_rxfilter
 */
static u_int32_t
ath_calcrxfilter(struct ath_softc *sc, enum ieee80211_state state)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	struct net_device *dev = ic->ic_dev;
	u_int32_t rfilt;

	rfilt = (ath_hal_getrxfilter(ah) & HAL_RX_FILTER_PHYERR)
	      | HAL_RX_FILTER_UCAST | HAL_RX_FILTER_BCAST | HAL_RX_FILTER_MCAST | HAL_RX_FILTER_PHYRADAR;
	if (ic->ic_opmode != IEEE80211_M_STA)
		rfilt |= HAL_RX_FILTER_PROBEREQ;
	if (ic->ic_opmode != IEEE80211_M_HOSTAP &&
	    (dev->flags & IFF_PROMISC))
		rfilt |= HAL_RX_FILTER_PROM;
	if (ic->ic_opmode == IEEE80211_M_STA ||
	    ic->ic_opmode == IEEE80211_M_IBSS ||
	    state == IEEE80211_S_SCAN)
		rfilt |= HAL_RX_FILTER_BEACON;

	rfilt |= sc->sc_rxfilter;
#ifdef HAS_CU_SOFTMAC
	if (sc->sc_cu_softmac) { //&& ic->ic_opmode == IEEE80211_M_MONITOR) {
	  // Make sure we receive ALL the packets from the hal when in "SDR"
	  // mode
	  rfilt = ATH_CU_SOFTMAC_HAL_RX_FILTER_ALLOWALL;
	}
#endif
	return rfilt;
}

static void
ath_mode_init(struct net_device *dev)
{
        struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	u_int32_t rfilt, mfilt[2], val;
	u_int8_t pos;
	struct dev_mc_list *mc;

	/* configure rx filter */
	rfilt = ath_calcrxfilter(sc, ic->ic_state);
	ath_hal_setrxfilter(ah, rfilt);

	/* configure operational mode */
	ath_hal_setopmode(ah);

	/*
	 * Handle any link-level address change.  Note that we only
	 * need to force ic_myaddr; any other addresses are handled
	 * as a byproduct of the ifnet code marking the interface
	 * down then up.
	 *
	 * XXX should get from lladdr instead of arpcom but that's more work
	 */
	IEEE80211_ADDR_COPY(ic->ic_myaddr, dev->dev_addr);
	ath_hal_setmac(ah, ic->ic_myaddr);

	/* calculate and install multicast filter */
	if ((dev->flags & IFF_ALLMULTI) == 0) {
		mfilt[0] = mfilt[1] = 0;
		for (mc = dev->mc_list; mc; mc = mc->next) {
			/* calculate XOR of eight 6bit values */
			val = LE_READ_4(mc->dmi_addr + 0);
			pos = (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
			val = LE_READ_4(mc->dmi_addr + 3);
			pos ^= (val >> 18) ^ (val >> 12) ^ (val >> 6) ^ val;
			pos &= 0x3f;
			mfilt[pos / 32] |= (1 << (pos % 32));
		}
	} else {
		mfilt[0] = mfilt[1] = ~0;
	}
	ath_hal_setmcastfilter(ah, mfilt[0], mfilt[1]);
	DPRINTF(sc, ATH_DEBUG_MODE, "%s: RX filter 0x%x, MC filter %08x:%08x\n",
		__func__, rfilt, mfilt[0], mfilt[1]);
}

/*
 * Set the slot time based on the current setting.
 */
static void
ath_setslottime(struct ath_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;

	if (ic->ic_flags & IEEE80211_F_SHSLOT)
		ath_hal_setslottime(ah, HAL_SLOT_TIME_9);
	else
		ath_hal_setslottime(ah, HAL_SLOT_TIME_20);
	sc->sc_updateslot = OK;
}

/*
 * Callback from the 802.11 layer to update the
 * slot time based on the current setting.
 */
static void
ath_updateslot(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

	/*
	 * When not coordinating the BSS, change the hardware
	 * immediately.  For other operation we defer the change
	 * until beacon updates have propagated to the stations.
	 */
	if (ic->ic_opmode == IEEE80211_M_HOSTAP)
		sc->sc_updateslot = UPDATE;
	else
		ath_setslottime(sc);
}

/*
 * Setup a h/w transmit queue for beacons.
 */
static int
ath_beaconq_setup(struct ath_hal *ah)
{
	HAL_TXQ_INFO qi;

	memset(&qi, 0, sizeof(qi));
	qi.tqi_aifs = HAL_TXQ_USEDEFAULT;
	qi.tqi_cwmin = HAL_TXQ_USEDEFAULT;
	qi.tqi_cwmax = HAL_TXQ_USEDEFAULT;
	/* NB: don't enable any interrupts */
	return ath_hal_setuptxqueue(ah, HAL_TX_QUEUE_BEACON, &qi);
}

/*
 * Allocate and setup an initial beacon frame.
 */
static int
ath_beacon_alloc(struct ath_softc *sc, struct ieee80211_node *ni)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_buf *bf;
	struct sk_buff *skb;

	bf = STAILQ_FIRST(&sc->sc_bbuf);
	if (bf == NULL) {
		DPRINTF(sc, ATH_DEBUG_BEACON, "%s: no dma buffers\n", __func__);
		sc->sc_stats.ast_be_nobuf++;	/* XXX */
		return ENOMEM;			/* XXX */
	}
	/*
	 * NB: the beacon data buffer must be 32-bit aligned;
	 * we assume the mbuf routines will return us something
	 * with this alignment (perhaps should assert).
	 */
	skb = ieee80211_beacon_alloc(ic, ni, &sc->sc_boff);
	if (skb == NULL) {
		DPRINTF(sc, ATH_DEBUG_BEACON, "%s: cannot get sk_buff\n",
			__func__);
		sc->sc_stats.ast_be_nobuf++;
		return ENOMEM;
	}

	if (bf->bf_skb != NULL) {
		bus_unmap_single(sc->sc_bdev,
			bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);
		dev_kfree_skb(bf->bf_skb);
		bf->bf_skb = NULL;
		bf->bf_node = NULL;
	}
	bf->bf_skb = skb;
	bf->bf_node = ieee80211_ref_node(ni);

	return 0; // TODO: return value
}

/*
 * Setup the beacon frame for transmit.
 */
static void
ath_beacon_setup(struct ath_softc *sc, struct ath_buf *bf)
{
#define	USE_SHPREAMBLE(_ic) \
	(((_ic)->ic_flags & (IEEE80211_F_SHPREAMBLE | IEEE80211_F_USEBARKER))\
		== IEEE80211_F_SHPREAMBLE)
	struct ieee80211_node *ni = bf->bf_node;
	struct ieee80211com *ic = ni->ni_ic;
	struct sk_buff *skb = bf->bf_skb;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_node *an = ATH_NODE(ni);
	struct ath_desc *ds;
	int antenna = sc->sc_txantenna;
	int flags;
	u_int8_t rate;

	bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
		skb->data, skb->len, BUS_DMA_TODEVICE);
	DPRINTF(sc, ATH_DEBUG_BEACON,
		"%s: skb %p [data %p len %u] skbaddr %p\n",
		__func__, skb, skb->data, skb->len, (caddr_t) bf->bf_skbaddr);
	if (BUS_DMA_MAP_ERROR(bf->bf_skbaddr)) {
		if_printf(&sc->sc_dev, "%s: DMA mapping failed\n", __func__);
		return;
	}
	
	/* setup descriptors */
	ds = bf->bf_desc;

	flags = HAL_TXDESC_NOACK;
	if (ic->ic_opmode == IEEE80211_M_IBSS && sc->sc_hasveol) {
		ds->ds_link = bf->bf_daddr;	/* self-linked */
		flags |= HAL_TXDESC_VEOL;
		/*
		 * Let hardware handle antenna switching if txantenna is not set
		 */
	} else {
		ds->ds_link = 0;
		/*
		 * Switch antenna every 4 beacons if txantenna is not set
		 * XXX assumes two antenna
		 */
		if (antenna == 0) {
			antenna = (sc->sc_stats.ast_be_xmit & 4 ? 2 : 1);
		}
	}

	ds->ds_data = bf->bf_skbaddr;
	/*
	 * Calculate rate code.
	 * XXX everything at min xmit rate
	 */
	if (USE_SHPREAMBLE(ic))
		rate = an->an_tx_mgtratesp;
	else
		rate = an->an_tx_mgtrate;
	ath_hal_setuptxdesc(ah, ds
		, skb->len + IEEE80211_CRC_LEN	/* frame length */
		, sizeof(struct ieee80211_frame)/* header length */
		, HAL_PKT_TYPE_BEACON		/* Atheros packet type */
		, ni->ni_txpower		/* txpower XXX */
		, rate, 1			/* series 0 rate/tries */
		, HAL_TXKEYIX_INVALID		/* no encryption */
		, antenna			/* antenna mode */
		, flags				/* no ack, veol for beacons */
		, 0				/* rts/cts rate */
		, 0				/* rts/cts duration */
	);
	/* NB: beacon's BufLen must be a multiple of 4 bytes */
	ath_hal_filltxdesc(ah, ds
		, roundup(skb->len, 4)		/* buffer length */
		, AH_TRUE			/* first segment */
		, AH_TRUE			/* last segment */
		, ds				/* first descriptor */
	);
#undef USE_SHPREAMBLE
}

/*
 * Transmit a beacon frame at SWBA.  Dynamic updates to the
 * frame contents are done as needed and the slot time is
 * also adjusted based on current state.
 */
static void
ath_beacon_tasklet(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_buf *bf = STAILQ_FIRST(&sc->sc_bbuf);
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	struct sk_buff *skb;
	int ncabq, otherant;

	DPRINTF(sc, ATH_DEBUG_BEACON_PROC, "%s\n", __func__);
	
	if (ic->ic_opmode == IEEE80211_M_STA ||
	    ic->ic_opmode == IEEE80211_M_MONITOR ||
	    bf == NULL || bf->bf_skb == NULL) {
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: ic_flags=%x bf=%p bf_skb=%p\n",
			__func__, ic->ic_flags, bf, bf ? bf->bf_skb : NULL);
		return;
	}
	/*
	 * Check if the previous beacon has gone out.  If
	 * not don't don't try to post another, skip this
	 * period and wait for the next.  Missed beacons
	 * indicate a problem and should not occur.  If we
	 * miss too many consecutive beacons reset the device.
	 */
	if (ath_hal_numtxpending(ah, sc->sc_bhalq) != 0) {
		sc->sc_bmisscount++;
		DPRINTF(sc, ATH_DEBUG_BEACON_PROC,
			"%s: missed %u consecutive beacons\n",
			__func__, sc->sc_bmisscount);
		if (sc->sc_bmisscount > 3) {		/* NB: 3 is a guess */
			DPRINTF(sc, ATH_DEBUG_BEACON_PROC,
			"%s: stuck beacon time (%u missed)\n",
			__func__, sc->sc_bmisscount);
                        ATH_SCHEDULE_TQUEUE(&sc->sc_bstuckq, &needmark);
                }
		return;
	}
	if (sc->sc_bmisscount != 0) {
		DPRINTF(sc, ATH_DEBUG_BEACON,
			"%s: resume beacon xmit after %u misses\n",
			__func__, sc->sc_bmisscount);
		sc->sc_bmisscount = 0;
	}

	/*
	 * Update dynamic beacon contents.  If this returns
	 * non-zero then we need to remap the memory because
	 * the beacon frame changed size (probably because
	 * of the TIM bitmap).
	 */
	skb = bf->bf_skb;
	ncabq = ath_hal_numtxpending(ah, sc->sc_cabq->axq_qnum);
	if (ieee80211_beacon_update(ic, bf->bf_node, &sc->sc_boff, skb, ncabq)) {
		DPRINTF(sc, ATH_DEBUG_BEACON_PROC,
			"%s: update, beacon len changed %d to %d\n",
			__func__, bf->bf_skb->len, skb->len);
		
		/* XXX too conservative? */
		bus_unmap_single(sc->sc_bdev,
			bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);

                bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
                    skb->data, skb->len, BUS_DMA_TODEVICE);
                if (BUS_DMA_MAP_ERROR(bf->bf_skbaddr)) {
			if_printf(dev, "%s: DMA mapping failed\n", __func__);
			return;
		}
	}

	/*
	 * Handle slot time change when a non-ERP station joins/leaves
	 * an 11g network.  The 802.11 layer notifies us via callback,
	 * we mark updateslot, then wait one beacon before effecting
	 * the change.  This gives associated stations at least one
	 * beacon interval to note the state change.
	 */
	/* XXX locking */
	if (sc->sc_updateslot == UPDATE)
		sc->sc_updateslot = COMMIT;	/* commit next beacon */
	else if (sc->sc_updateslot == COMMIT)
		ath_setslottime(sc);		/* commit change to h/w */

	/*
	 * Check recent per-antenna transmit statistics and flip
	 * the default antenna if noticeably more frames went out
	 * on the non-default antenna.
	 * XXX assumes 2 anntenae
	 */
	otherant = sc->sc_defant & 1 ? 2 : 1;
	if (sc->sc_ant_tx[otherant] > sc->sc_ant_tx[sc->sc_defant] + 2)
		ath_setdefantenna(sc, otherant);
	sc->sc_ant_tx[1] = sc->sc_ant_tx[2] = 0;

	/*
	 * Construct tx descriptor.
	 */
	ath_beacon_setup(sc, bf);

	/*
	 * Stop any current dma and put the new frame on the queue.
	 * This should never fail since we check above that no frames
	 * are still pending on the queue.
	 */
	if (!ath_hal_stoptxdma(ah, sc->sc_bhalq)) {
		DPRINTF(sc, ATH_DEBUG_ANY,
			"%s: beacon queue %u did not stop?\n",
			__func__, sc->sc_bhalq);
		/* NB: the HAL still stops DMA, so proceed */
	}
	bus_dma_sync_single(sc->sc_bdev,
		bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);

	/*
	 * Enable the CAB queue before the beacon queue to
	 * insure CAB frames are triggered by this beacon.
	 * The CAB queue holds multicast traffic for stations in 
	 * power-save mode.
	 *
	 * NB: only at DTIM
	 */
	if (ic->ic_opmode == IEEE80211_M_HOSTAP &&
	    ncabq > 0 && sc->sc_boff.bo_tim[4] & 1)
		ath_hal_txstart(ah, sc->sc_cabq->axq_qnum);
	ath_hal_puttxbuf(ah, sc->sc_bhalq, bf->bf_daddr);
	ath_hal_txstart(ah, sc->sc_bhalq);
	DPRINTF(sc, ATH_DEBUG_BEACON_PROC,
		"%s: TXDP[%u] = %p (%p)\n", __func__,
		sc->sc_bhalq, (caddr_t)bf->bf_daddr, bf->bf_desc);

	sc->sc_stats.ast_be_xmit++;
}

/*
 * Reset the hardware after detecting beacons have stopped.
 */
static void
ath_bstuck_tasklet(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;

	if_printf(dev, "stuck beacon; resetting (bmiss count %u)\n",
		sc->sc_bmisscount);
	ath_reset(dev);
}

/*
 * Reclaim beacon resources.
 */
static void
ath_beacon_free(struct ath_softc *sc)
{
	struct ath_buf *bf;

	STAILQ_FOREACH(bf, &sc->sc_bbuf, bf_list) {
            if (bf->bf_skb != NULL) {
		bus_unmap_single(sc->sc_bdev,
                    bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);
                dev_kfree_skb(bf->bf_skb);
                bf->bf_skb = NULL;
            }
            if (bf->bf_node != NULL) {
                ieee80211_free_node(bf->bf_node);
                bf->bf_node = NULL;
            }
	}
}

/*
 * Configure the beacon and sleep timers.
 *
 * When operating as an AP this resets the TSF and sets
 * up the hardware to notify us when we need to issue beacons.
 *
 * When operating in station mode this sets up the beacon
 * timers according to the timestamp of the last received
 * beacon and the current TSF, configures PCF and DTIM
 * handling, programs the sleep registers so the hardware
 * will wakeup in time to receive beacons, and configures
 * the beacon miss handling so we'll receive a BMISS
 * interrupt when we stop seeing beacons from the AP
 * we've associated with.
 */
static void
ath_beacon_config(struct ath_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ieee80211_node *ni = ic->ic_bss;
	u_int32_t nexttbtt, intval;

	nexttbtt = (LE_READ_4(ni->ni_tstamp.data + 4) << 22) |
	    (LE_READ_4(ni->ni_tstamp.data) >> 10);
	intval = ni->ni_intval & HAL_BEACON_PERIOD;
	if (nexttbtt == 0)		/* e.g. for ap mode */
		nexttbtt = intval;
	else if (intval)		/* NB: can be 0 for monitor mode */
		nexttbtt = roundup(nexttbtt, intval); 
	DPRINTF(sc, ATH_DEBUG_BEACON, "%s: nexttbtt %u intval %u (%u)\n",
		__func__, nexttbtt, intval, ni->ni_intval);
	if (ic->ic_opmode == IEEE80211_M_STA) {
		HAL_BEACON_STATE bs;

		/* NB: no PCF support right now */
		memset(&bs, 0, sizeof(bs));
		bs.bs_intval = intval;
		bs.bs_nexttbtt = nexttbtt;
		bs.bs_dtimperiod = bs.bs_intval;
		bs.bs_nextdtim = nexttbtt;
		/*
		 * The 802.11 layer records the offset to the DTIM
		 * bitmap while receiving beacons; use it here to
		 * enable h/w detection of our AID being marked in
		 * the bitmap vector (to indicate frames for us are
		 * pending at the AP).
		 */
		bs.bs_timoffset = ni->ni_timoff;
		/*
		 * Calculate the number of consecutive beacons to miss
		 * before taking a BMISS interrupt.  The configuration
		 * is specified in ms, so we need to convert that to
		 * TU's and then calculate based on the beacon interval.
		 * Note that we clamp the result to at most 10 beacons.
		 */
		bs.bs_bmissthreshold = howmany(ic->ic_bmisstimeout, intval);
		if (bs.bs_bmissthreshold > 10)
			bs.bs_bmissthreshold = 10;
		else if (bs.bs_bmissthreshold <= 0)
			bs.bs_bmissthreshold = 1;

		/*
		 * Calculate sleep duration.  The configuration is
		 * given in ms.  We insure a multiple of the beacon
		 * period is used.  Also, if the sleep duration is
		 * greater than the DTIM period then it makes senses
		 * to make it a multiple of that.
		 *
		 * XXX fixed at 100ms
		 */
		bs.bs_sleepduration =
			roundup(IEEE80211_MS_TO_TU(100), bs.bs_intval);
		if (bs.bs_sleepduration > bs.bs_dtimperiod)
			bs.bs_sleepduration = roundup(bs.bs_sleepduration, bs.bs_dtimperiod);

		DPRINTF(sc, ATH_DEBUG_BEACON, 
			"%s: intval %u nexttbtt %u dtim %u nextdtim %u bmiss %u sleep %u cfp:period %u maxdur %u next %u timoffset %u\n"
			, __func__
			, bs.bs_intval
			, bs.bs_nexttbtt
			, bs.bs_dtimperiod
			, bs.bs_nextdtim
			, bs.bs_bmissthreshold
			, bs.bs_sleepduration
			, bs.bs_cfpperiod
			, bs.bs_cfpmaxduration
			, bs.bs_cfpnext
			, bs.bs_timoffset
		);
		ath_hal_intrset(ah, 0);
		ath_hal_beacontimers(ah, &bs);
		sc->sc_imask |= HAL_INT_BMISS;
		ath_hal_intrset(ah, sc->sc_imask);
	} else {
		ath_hal_intrset(ah, 0);
		if (nexttbtt == intval)
			intval |= HAL_BEACON_RESET_TSF;
		if (ic->ic_opmode == IEEE80211_M_IBSS) {
			/*
			 * In IBSS mode enable the beacon timers but only
			 * enable SWBA interrupts if we need to manually
			 * prepare beacon frames.  Otherwise we use a
			 * self-linked tx descriptor and let the hardware
			 * deal with things.
			 */
			intval |= HAL_BEACON_ENA;
			if (!sc->sc_hasveol)
				sc->sc_imask |= HAL_INT_SWBA;
		} else if (ic->ic_opmode == IEEE80211_M_HOSTAP) {
			/*
			 * In AP mode we enable the beacon timers and
			 * SWBA interrupts to prepare beacon frames.
			 */
			intval |= HAL_BEACON_ENA;
			sc->sc_imask |= HAL_INT_SWBA;	/* beacon prepare */
		}
		ath_hal_beaconinit(ah, nexttbtt, intval);
		sc->sc_bmisscount = 0;
		ath_hal_intrset(ah, sc->sc_imask);
		/*
		 * When using a self-linked beacon descriptor in
		 * ibss mode load it once here.
		 */
		if (ic->ic_opmode == IEEE80211_M_IBSS && sc->sc_hasveol)
			ath_beacon_tasklet(&sc->sc_dev);
	}
}

static void
ath_descdma_cleanup(struct ath_softc *sc, ath_bufhead *head)
{
	struct ath_buf *bf;
	struct ieee80211_node *ni;

	STAILQ_FOREACH(bf, head, bf_list){
		if (bf->bf_skb) {
			bus_unmap_single(sc->sc_bdev,
				bf->bf_skbaddr, sc->sc_rxbufsize,
				BUS_DMA_FROMDEVICE);
			dev_kfree_skb(bf->bf_skb);
			bf->bf_skb = NULL;
		}
		ni = bf->bf_node;
		bf->bf_node = NULL;
		if (ni != NULL) {
			/*
			 * Reclaim node reference.
			 */
			ieee80211_free_node(ni);
		}
	}

	STAILQ_INIT(head);
}

static int
ath_desc_alloc(struct ath_softc *sc)
{
#define	DS2PHYS(_sc, _ds) \
	((_sc)->sc_desc_daddr + ((caddr_t)(_ds) - (caddr_t)(_sc)->sc_desc))
	int bsize;
	struct ath_desc *ds;
	struct ath_buf *bf;
	int i;

	/* allocate descriptors */
	sc->sc_desc_len = sizeof(struct ath_desc) *
				(ATH_TXBUF * ATH_TXDESC + ATH_RXBUF + ATH_BCBUF + 1);
	sc->sc_desc = bus_alloc_consistent(sc->sc_bdev,
				sc->sc_desc_len, &sc->sc_desc_daddr);
	if (sc->sc_desc == NULL) {
		if_printf(&sc->sc_dev, "%s, could not allocate descriptors\n", __func__);
		return ENOMEM;
	}
	ds = sc->sc_desc;
	DPRINTF(sc, ATH_DEBUG_ANY, "%s: DMA map: %p (%u) -> %p\n",
	    __func__, ds, (unsigned int) sc->sc_desc_len, (caddr_t) sc->sc_desc_daddr);

	/* allocate buffers */
	bsize = sizeof(struct ath_buf) * (ATH_TXBUF + ATH_RXBUF + ATH_BCBUF + 1);
	bf = kmalloc(bsize, GFP_KERNEL);
	if (bf == NULL)
		goto bad;
	memset(bf, 0, bsize);
	sc->sc_bufptr = bf;

	STAILQ_INIT(&sc->sc_rxbuf);
	for (i = 0; i < ATH_RXBUF; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(sc, ds);
		STAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
	}

	STAILQ_INIT(&sc->sc_txbuf);
	for (i = 0; i < ATH_TXBUF; i++, bf++, ds += ATH_TXDESC) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(sc, ds);
		STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
	}

	STAILQ_INIT(&sc->sc_bbuf);
	for (i = 0; i < ATH_BCBUF; i++, bf++, ds++) {
		bf->bf_desc = ds;
		bf->bf_daddr = DS2PHYS(sc, ds);
		STAILQ_INSERT_TAIL(&sc->sc_bbuf, bf, bf_list);
	}

	return 0;
bad:
	bus_free_consistent(sc->sc_bdev, sc->sc_desc_len,
		sc->sc_desc, sc->sc_desc_daddr);
	sc->sc_desc = NULL;
	return ENOMEM;
#undef DS2PHYS
}

static void
ath_desc_free(struct ath_softc *sc)
{
        ath_descdma_cleanup(sc, &sc->sc_bbuf);
        ath_descdma_cleanup(sc, &sc->sc_txbuf);
        ath_descdma_cleanup(sc, &sc->sc_rxbuf);

	/* Free memory associated with all descriptors */
	bus_free_consistent(sc->sc_bdev, sc->sc_desc_len,
		sc->sc_desc, sc->sc_desc_daddr);

	kfree(sc->sc_bufptr);
	sc->sc_bufptr = NULL;
}

static struct ieee80211_node *
ath_node_alloc(struct ieee80211_node_table *nt)
{
	struct ieee80211com *ic = nt->nt_ic;
	struct ath_softc *sc = ic->ic_dev->priv;
	const size_t space = sizeof(struct ath_node) + sc->sc_rc->arc_space;
	struct ath_node *an;

	an = kmalloc(space, GFP_ATOMIC);
	if (an == NULL) {
		/* XXX stat+msg */
		return NULL;
	}
	memset(an, 0, space);
	an->an_avgrssi = ATH_RSSI_DUMMY_MARKER;
	an->an_halstats.ns_avgbrssi = ATH_RSSI_DUMMY_MARKER;
	an->an_halstats.ns_avgrssi = ATH_RSSI_DUMMY_MARKER;
	an->an_halstats.ns_avgtxrssi = ATH_RSSI_DUMMY_MARKER;
	ath_rate_node_init(sc, an);

	DPRINTF(sc, ATH_DEBUG_NODE, "%s: an %p\n", __func__, an);
	return &an->an_node;
}

static void
ath_node_free(struct ieee80211_node *ni)
{
	struct ieee80211com *ic = ni->ni_ic;
        struct ath_softc *sc = ic->ic_dev->priv;
	DPRINTF(sc, ATH_DEBUG_NODE, "%s: ni %p\n", __func__, ni);
/* 
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++)		// TODO: seems we need this still
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_cleanq(&sc->sc_txq[i], ni);
*/
	ath_rate_node_cleanup(sc, ATH_NODE(ni));
	sc->sc_node_free(ni);
}

static u_int8_t
ath_node_getrssi(const struct ieee80211_node *ni)
{
#define	HAL_EP_RND(x, mul) \
	((((x)%(mul)) >= ((mul)/2)) ? ((x) + ((mul) - 1)) / (mul) : (x)/(mul))
	u_int32_t avgrssi = ATH_NODE_CONST(ni)->an_avgrssi;
	int32_t rssi;

	/*
	 * When only one frame is received there will be no state in
	 * avgrssi so fallback on the value recorded by the 802.11 layer.
	 */
	if (avgrssi != ATH_RSSI_DUMMY_MARKER)
		rssi = HAL_EP_RND(avgrssi, HAL_RSSI_EP_MULTIPLIER);
	else
		rssi = ni->ni_rssi;
	/* NB: theoretically we shouldn't need this, but be paranoid */
	return rssi < 0 ? 0 : rssi > 127 ? 127 : rssi;
#undef HAL_EP_RND
}

static int
ath_rxbuf_init(struct ath_softc *sc, struct ath_buf *bf)
{
	struct ath_hal *ah = sc->sc_ah;
	struct sk_buff *skb;
	struct ath_desc *ds;
	int headroom_needed = 0;
	
	if (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR) {
		headroom_needed = sizeof(wlan_ng_prism2_header);
	} else if (sc->sc_rawdev.type == ARPHRD_IEEE80211_PRISM) {
		headroom_needed = sizeof(wlan_ng_prism2_header);
	} else if (sc->sc_rawdev.type == ARPHRD_IEEE80211_RADIOTAP) {
		headroom_needed = sizeof(struct ath_rx_radiotap_header);
	}

	/* 
	 * Check if we have enough headroom. If not, just free the skb
	 * and we'll alloc another one below.
	 */
	if (bf->bf_skb && skb_headroom(bf->bf_skb) < headroom_needed) {
		bus_unmap_single(sc->sc_bdev,
				 bf->bf_skbaddr, sc->sc_rxbufsize,
				 BUS_DMA_FROMDEVICE);
		dev_kfree_skb(bf->bf_skb);
		bf->bf_skb = NULL;
	}

	skb = bf->bf_skb;

	if (skb == NULL) {
		u_int off;

		/*
		 * Allocate buffer with headroom_needed space for the
		 * fake physical layer header at the start.
		 */
		skb = dev_alloc_skb(sc->sc_rxbufsize +
				    headroom_needed + 
				    sc->sc_cachelsz - 1);
		if (skb == NULL) {
			DPRINTF(sc, ATH_DEBUG_ANY,
				"%s: skbuff alloc of size %d failed\n",
				__func__,
				(int)(sc->sc_rxbufsize
				      + headroom_needed
				      + sc->sc_cachelsz - 1));
			sc->sc_stats.ast_rx_nobuf++;
			return ENOMEM;
		}
		/*
		 * Reserve space for the fake physical layer header.
		 */
		skb_reserve(skb, headroom_needed);
		/*
		 * Cache-line-align.  This is important (for the
		 * 5210 at least) as not doing so causes bogus data
		 * in rx'd frames.
		 */
		off = ((unsigned long) skb->data) % sc->sc_cachelsz;
		if (off != 0)
			skb_reserve(skb, sc->sc_cachelsz - off);

		skb->dev = &sc->sc_dev;
		bf->bf_skb = skb;
		bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
			skb->data, sc->sc_rxbufsize, BUS_DMA_FROMDEVICE);
		if (BUS_DMA_MAP_ERROR(bf->bf_skbaddr)) {
			if_printf(&sc->sc_dev, "%s: DMA mapping failed\n", __func__);
			dev_kfree_skb(skb);
			bf->bf_skb = NULL;
			sc->sc_stats.ast_rx_busdma++;
			return ENOMEM;
		}
	}

	/*
	 * Setup descriptors.  For receive we always terminate
	 * the descriptor list with a self-linked entry so we'll
	 * not get overrun under high load (as can happen with a
	 * 5212 when ANI processing enables PHY error frames).
	 *
	 * To insure the last descriptor is self-linked we create
	 * each descriptor as self-linked and add it to the end.  As
	 * each additional descriptor is added the previous self-linked
	 * entry is ``fixed'' naturally.  This should be safe even
	 * if DMA is happening.  When processing RX interrupts we
	 * never remove/process the last, self-linked, entry on the
	 * descriptor list.  This insures the hardware always has
	 * someplace to write a new frame.
	 */
	ds = bf->bf_desc;
	ds->ds_link = bf->bf_daddr;	/* link to self */
	ds->ds_data = bf->bf_skbaddr;
	ath_hal_setuprxdesc(ah, ds
		, skb_tailroom(skb)	/* buffer size */
		, 0
	);

	if (sc->sc_rxlink != NULL)
		*sc->sc_rxlink = bf->bf_daddr;
	sc->sc_rxlink = &ds->ds_link;
	return 0;
}

/*
 * Add additional headers to a transmitted frame and netif_rx it on
 * a monitor or raw device
 */
static void
ath_tx_capture(struct net_device *dev, struct ath_desc *ds, struct sk_buff *skb)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	u_int32_t tsf;

	/* 
	 * release the owner of this skb since we're basically
	 * recycling it 
	 */
	if (atomic_read(&skb->users) != 1) {
		struct sk_buff *skb2 = skb;
		skb = skb_clone(skb, GFP_ATOMIC);
		if (skb == NULL) {
			dev_kfree_skb(skb2);
			return;
		}
		kfree_skb(skb2);
	} else {
		skb_orphan(skb);
	}

	switch (dev->type) {
	case ARPHRD_IEEE80211:
		break;
	case ARPHRD_IEEE80211_PRISM: {
		wlan_ng_prism2_header *ph;
		if (skb_headroom(skb) < sizeof(wlan_ng_prism2_header) &&
		    pskb_expand_head(skb, 
				     sizeof(wlan_ng_prism2_header), 
				     0, GFP_ATOMIC)) {
			DPRINTF(sc, ATH_DEBUG_RECV, 
				"%s: couldn't pskb_expand_head\n", __func__);
			goto bad;
		}

		ph = (wlan_ng_prism2_header *)
			skb_push(skb, sizeof(wlan_ng_prism2_header));
		memset(ph, 0, sizeof(wlan_ng_prism2_header));
		
		ph->msgcode = DIDmsg_lnxind_wlansniffrm;
		ph->msglen = sizeof(wlan_ng_prism2_header);
		strcpy(ph->devname, sc->sc_dev.name);
		
		ph->hosttime.did = DIDmsg_lnxind_wlansniffrm_hosttime;
		ph->hosttime.status = 0;
		ph->hosttime.len = 4;
		ph->hosttime.data = jiffies;
		
		/* Pass up tsf clock in mactime */
		ph->mactime.did = DIDmsg_lnxind_wlansniffrm_mactime;
		ph->mactime.status = 0;
		ph->mactime.len = 4;
		/*
		 * Rx descriptor has the low 15 bits of the tsf at
		 * the time the frame was received.  Use the current
		 * tsf to extend this to 32 bits.
		 */
		tsf = ath_hal_gettsf32(sc->sc_ah);
		if ((tsf & 0x7fff) < ds->ds_rxstat.rs_tstamp)
			tsf -= 0x8000;
		ph->mactime.data = ds->ds_rxstat.rs_tstamp | (tsf &~ 0x7fff);
		
		ph->istx.did = DIDmsg_lnxind_wlansniffrm_istx;
		ph->istx.status = 0;
		ph->istx.len = 4;
		ph->istx.data = P80211ENUM_truth_true;
		
		ph->frmlen.did = DIDmsg_lnxind_wlansniffrm_frmlen;
		ph->frmlen.status = 0;
		ph->frmlen.len = 4;
		ph->frmlen.data = ds->ds_rxstat.rs_datalen;
		
		ph->channel.did = DIDmsg_lnxind_wlansniffrm_channel;
		ph->channel.status = 0;
		ph->channel.len = 4;
		ph->channel.data = ieee80211_mhz2ieee(ic->ic_ibss_chan->ic_freq,0);
		
		ph->rssi.did = DIDmsg_lnxind_wlansniffrm_rssi;
		ph->rssi.status = 0;
		ph->rssi.len = 4;
		ph->rssi.data = ds->ds_rxstat.rs_rssi;
		
		ph->noise.did = DIDmsg_lnxind_wlansniffrm_noise;
		ph->noise.status = 0;
		ph->noise.len = 4;
		ph->noise.data = -95;
		
		ph->signal.did = DIDmsg_lnxind_wlansniffrm_signal;
		ph->signal.status = 0;
		ph->signal.len = 4;
		ph->signal.data = -95 + ds->ds_rxstat.rs_rssi;
		
		ph->rate.did = DIDmsg_lnxind_wlansniffrm_rate;
		ph->rate.status = 0;
		ph->rate.len = 4;
		ph->rate.data = sc->sc_hwmap[ds->ds_txstat.ts_rate &~ HAL_TXSTAT_ALTRATE].ieeerate;
		break;
	}
	case ARPHRD_IEEE80211_RADIOTAP: {
		struct ath_tx_radiotap_header *th;

		if (skb_headroom(skb) < sizeof(struct ath_tx_radiotap_header) &&
		    pskb_expand_head(skb, 
				     sizeof(struct ath_tx_radiotap_header), 
				     0, GFP_ATOMIC)) {
			DPRINTF(sc, ATH_DEBUG_RECV, 
				"%s: couldn't pskb_expand_head\n", __func__);
			goto bad;
		}
		
		th = (struct ath_tx_radiotap_header *) skb_push(skb, sizeof(struct ath_tx_radiotap_header));
		memset(th, 0, sizeof(struct ath_tx_radiotap_header));
		th->wt_ihdr.it_version = 0;
		th->wt_ihdr.it_len = sizeof(struct ath_tx_radiotap_header);
		th->wt_ihdr.it_present = ATH_TX_RADIOTAP_PRESENT;
		th->wt_flags = 0;
		th->wt_rate = sc->sc_hwmap[ds->ds_txstat.ts_rate &~ HAL_TXSTAT_ALTRATE].ieeerate;
		th->wt_txpower = 0;
		th->wt_antenna = ds->ds_txstat.ts_antenna;
		th->wt_tx_flags = 0;
		if (ds->ds_txstat.ts_status) 
			th->wt_tx_flags |= IEEE80211_RADIOTAP_F_TX_FAIL;
		th->wt_rts_retries = ds->ds_txstat.ts_shortretry;
		th->wt_data_retries = ds->ds_txstat.ts_longretry;
		
		break;
	}
	default:
		break;
	}

	skb->dev = dev;
	skb->mac.raw = skb->data;
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(0x0019);  /* ETH_P_80211_RAW */
	netif_rx(skb);
	return;

 bad:
	dev_kfree_skb(skb);
	return;
}

/*
 * Add additional headers to a received frame and netif_rx it on
 * a monitor or raw device
 */
static void
ath_rx_capture(struct net_device *dev, struct ath_desc *ds, struct sk_buff *skb)
{
#define	IS_QOS_DATA(wh) \
	((wh->i_fc[0] & (IEEE80211_FC0_TYPE_MASK|IEEE80211_FC0_SUBTYPE_MASK))==\
		(IEEE80211_FC0_TYPE_DATA | IEEE80211_FC0_SUBTYPE_QOS))
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	int len = ds->ds_rxstat.rs_datalen;
	struct ieee80211_frame *wh;
	u_int32_t tsf;

	KASSERT(ic->ic_flags & IEEE80211_F_DATAPAD,
		("data padding not enabled?"));
	/* Remove pad bytes */
	wh = (struct ieee80211_frame *) skb->data;
	if (IS_QOS_DATA(wh)) {
		int headersize = ieee80211_hdrsize(wh);
		int padbytes = roundup(headersize,4) - headersize;

		/*
		 * Copy up 802.11 header and strip h/w padding.
		 */
		if (padbytes > 0) {
			memmove(skb->data + padbytes, skb->data, headersize);
			skb_pull(skb, padbytes);
			len -= padbytes;
		}
	}

	switch (dev->type) {
	case ARPHRD_IEEE80211:
		break;
	case ARPHRD_IEEE80211_PRISM: {
		wlan_ng_prism2_header *ph;
		if (skb_headroom(skb) < sizeof(wlan_ng_prism2_header)) {
			DPRINTF(sc, ATH_DEBUG_RECV,
				"%s: prism not enough headroom %d/%d\n",
				__func__, skb_headroom(skb), 
				sizeof(wlan_ng_prism2_header));
			goto bad;
		}
		ph = (wlan_ng_prism2_header *)
			skb_push(skb, sizeof(wlan_ng_prism2_header));
		memset(ph, 0, sizeof(wlan_ng_prism2_header));
		
		ph->msgcode = DIDmsg_lnxind_wlansniffrm;
		ph->msglen = sizeof(wlan_ng_prism2_header);
		strcpy(ph->devname, sc->sc_dev.name);
		
		ph->hosttime.did = DIDmsg_lnxind_wlansniffrm_hosttime;
		ph->hosttime.status = 0;
		ph->hosttime.len = 4;
		ph->hosttime.data = jiffies;
		
		/* Pass up tsf clock in mactime */
		ph->mactime.did = DIDmsg_lnxind_wlansniffrm_mactime;
		ph->mactime.status = 0;
		ph->mactime.len = 4;
		/*
		 * Rx descriptor has the low 15 bits of the tsf at
		 * the time the frame was received.  Use the current
		 * tsf to extend this to 32 bits.
		 */
		tsf = ath_hal_gettsf32(sc->sc_ah);
		if ((tsf & 0x7fff) < ds->ds_rxstat.rs_tstamp)
			tsf -= 0x8000;
		ph->mactime.data = ds->ds_rxstat.rs_tstamp | (tsf &~ 0x7fff);
		
		ph->istx.did = DIDmsg_lnxind_wlansniffrm_istx;
		ph->istx.status = 0;
		ph->istx.len = 4;
		ph->istx.data = P80211ENUM_truth_false;
		
		ph->frmlen.did = DIDmsg_lnxind_wlansniffrm_frmlen;
		ph->frmlen.status = 0;
		ph->frmlen.len = 4;
		ph->frmlen.data = len;
		
		ph->channel.did = DIDmsg_lnxind_wlansniffrm_channel;
		ph->channel.status = 0;
		ph->channel.len = 4;
		ph->channel.data = ieee80211_mhz2ieee(ic->ic_ibss_chan->ic_freq,0);
		
		ph->rssi.did = DIDmsg_lnxind_wlansniffrm_rssi;
		ph->rssi.status = 0;
		ph->rssi.len = 4;
		ph->rssi.data = ds->ds_rxstat.rs_rssi;
		
		ph->noise.did = DIDmsg_lnxind_wlansniffrm_noise;
		ph->noise.status = 0;
		ph->noise.len = 4;
		ph->noise.data = -95;
		
		ph->signal.did = DIDmsg_lnxind_wlansniffrm_signal;
		ph->signal.status = 0;
		ph->signal.len = 4;
		ph->signal.data = -95 + ds->ds_rxstat.rs_rssi;
		
		ph->rate.did = DIDmsg_lnxind_wlansniffrm_rate;
		ph->rate.status = 0;
		ph->rate.len = 4;
		ph->rate.data = sc->sc_hwmap[ds->ds_rxstat.rs_rate].ieeerate;
		break;
	}
	case ARPHRD_IEEE80211_RADIOTAP: {
		struct ath_rx_radiotap_header *th;
		if (skb_headroom(skb) < sizeof(struct ath_rx_radiotap_header)) {
			DPRINTF(sc, ATH_DEBUG_RECV,
				"%s: radiotap not enough headroom %d/%d\n",
				__func__, skb_headroom(skb), 
				sizeof(struct ath_rx_radiotap_header));
			goto bad;
		}
		th = (struct ath_rx_radiotap_header  *) skb_push(skb, sizeof(struct ath_rx_radiotap_header));
		memset(th, 0, sizeof(struct ath_rx_radiotap_header));

		th->wr_ihdr.it_version = 0;
		th->wr_ihdr.it_len = sizeof(struct ath_rx_radiotap_header);
		th->wr_ihdr.it_present = ATH_RX_RADIOTAP_PRESENT;
		th->wr_flags = IEEE80211_RADIOTAP_F_FCS;
		th->wr_rate = sc->sc_hwmap[ds->ds_rxstat.rs_rate].ieeerate;
		th->wr_chan_freq = ic->ic_ibss_chan->ic_freq;
		th->wr_chan_flags = ic->ic_ibss_chan->ic_flags;
		th->wr_antenna = ds->ds_rxstat.rs_antenna;
		th->wr_antsignal = ds->ds_rxstat.rs_rssi;
		th->wr_rx_flags = 0;
		if (ds->ds_rxstat.rs_status & HAL_RXERR_CRC)
			th->wr_rx_flags |= IEEE80211_RADIOTAP_F_RX_BADFCS;

		break;
	}
	default:
		break;
	}
	
	skb->dev = dev;
	skb->mac.raw = skb->data;
	skb->ip_summed = CHECKSUM_NONE;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(0x0019);  /* ETH_P_80211_RAW */

	netif_rx(skb);
	return;

 bad:
	dev_kfree_skb(skb);
	return;
#undef IS_QOS_DATA
}

/*
 * Extend 15-bit time stamp from rx descriptor to
 * a full 64-bit TSF using the current h/w TSF.
 */
static inline uint64_t
ath_tsf_extend(struct ath_hal *ah, uint32_t rstamp)
{
	uint64_t tsf;

	tsf = ath_hal_gettsf64(ah);

	/* Compensate for rollover. */
	if ((tsf & 0x7fff) < rstamp)
		tsf -= 0x8000;
	
	return ((tsf & ~(uint64_t)0x7fff) | rstamp);
}

/*
 * Intercept management frames to collect beacon rssi data
 * and to do ibss merges.
 */
static void
ath_recv_mgmt(struct ieee80211com *ic, struct sk_buff *skb,
	struct ieee80211_node *ni,
	int subtype, int rssi, u_int32_t rstamp)
{
	struct ath_softc *sc = ic->ic_dev->priv;

	/*
	 * Call up first so subsequent work can use information
	 * potentially stored in the node (e.g. for ibss merge).
	 */
	sc->sc_recv_mgmt(ic, skb, ni, subtype, rssi, rstamp);
	switch (subtype) {
	case IEEE80211_FC0_SUBTYPE_BEACON:
		/* update rssi statistics for use by the hal */
		ATH_RSSI_LPF((ATH_NODE(ni))->an_halstats.ns_avgbrssi, rssi);
		/* fall thru... */
	case IEEE80211_FC0_SUBTYPE_PROBE_RESP:
		if (ic->ic_opmode == IEEE80211_M_IBSS &&
		    ic->ic_state == IEEE80211_S_RUN) {
			/* Extend rstamp with the current tsf to 64 bit */
			u_int64_t tsf = ath_tsf_extend(sc->sc_ah, rstamp);
			/*
			 * Handle ibss merge as needed; check the tsf on the
			 * frame before attempting the merge.  The 802.11 spec
			 * says the station should change it's bssid to match
			 * the oldest station with the same ssid, where oldest
			 * is determined by the tsf.  Note that hardware
			 * reconfiguration happens through callback to
			 * ath_newstate as the state machine will go from
			 * RUN -> RUN when this happens.
			 */
			if (le64toh(ni->ni_tstamp.tsf) >= tsf) {
				DPRINTF(sc, ATH_DEBUG_STATE,
				    "ibss merge, rstamp %u tsf %llx "
				    "tstamp %llx\n", rstamp, tsf,
				    ni->ni_tstamp.tsf);
				ieee80211_ibss_merge(ic, ni);
			}
		}
		break;
	}
}

/*
 * Set the default antenna.
 */
static void
ath_setdefantenna(struct ath_softc *sc, u_int antenna)
{
	struct ath_hal *ah = sc->sc_ah;

	/* XXX block beacon interrupts */
	ath_hal_setdefantenna(ah, antenna);
	if (sc->sc_defant != antenna)
		sc->sc_stats.ast_ant_defswitch++;
	sc->sc_defant = antenna;
	sc->sc_rxotherant = 0;
}

static void
ath_rx_tasklet(TQUEUE_ARG data)
{
#define	PA2DESC(_sc, _pa) \
	((struct ath_desc *)((caddr_t)(_sc)->sc_desc + \
		((_pa) - (_sc)->sc_desc_daddr)))
	struct net_device *dev = (struct net_device *)data;
	struct ath_buf *bf;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	struct ath_desc *ds;
	struct sk_buff *skb;
	struct ieee80211_node *ni;
	struct ath_node *an;
	int len, type;
	u_int phyerr;
	HAL_STATUS status;

	DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s\n", __func__);
#ifdef HAS_CU_SOFTMAC
	if ((sc->sc_cu_softmac) /*&&
	    (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR)*/) {
	  ath_cu_softmac_rx_tasklet(data);
	  return;
	}
#endif
	do {
		bf = STAILQ_FIRST(&sc->sc_rxbuf);
		if (bf == NULL) {		/* XXX ??? can this happen */
			if_printf(dev, "%s: no buffer!\n", __func__);
			break;
		}
		ds = bf->bf_desc;
		if (ds->ds_link == bf->bf_daddr) {
			/* NB: never process the self-linked entry at the end */
			break;
		}
		skb = bf->bf_skb;
		if (skb == NULL) {		/* XXX ??? can this happen */
			if_printf(dev, "%s: no skbuff!\n", __func__);
			continue;
		}
		/* XXX sync descriptor memory */
		/*
		 * Must provide the virtual address of the current
		 * descriptor, the physical address, and the virtual
		 * address of the next descriptor in the h/w chain.
		 * This allows the HAL to look ahead to see if the
		 * hardware is done with a descriptor by checking the
		 * done bit in the following descriptor and the address
		 * of the current descriptor the DMA engine is working
		 * on.  All this is necessary because of our use of
		 * a self-linked list to avoid rx overruns.
		 */
		status = ath_hal_rxprocdesc(ah, ds,
				bf->bf_daddr, PA2DESC(sc, ds->ds_link));
#ifdef AR_DEBUG
		if (sc->sc_debug & ATH_DEBUG_RECV_DESC)
			ath_printrxbuf(bf, status == HAL_OK); 
#endif
		if (status == HAL_EINPROGRESS)
			break;
		STAILQ_REMOVE_HEAD(&sc->sc_rxbuf, bf_list);
		if (ds->ds_rxstat.rs_more) {
			/*
			 * Frame spans multiple descriptors; this
			 * cannot happen yet as we don't support
			 * jumbograms.  If not in monitor mode,
			 * discard the frame.
			 */
#ifndef ERROR_FRAMES
			/*
			 * Enable this if you want to see
			 * error frames in Monitor mode.
			 */
			if (ic->ic_opmode != IEEE80211_M_MONITOR) {
				sc->sc_stats.ast_rx_toobig++;
				goto rx_next;
			}
#endif
			/* fall thru for monitor mode handling... */
		} else if (ds->ds_rxstat.rs_status != 0) {
			if (ds->ds_rxstat.rs_status & HAL_RXERR_CRC)
				sc->sc_stats.ast_rx_crcerr++;
			if (ds->ds_rxstat.rs_status & HAL_RXERR_FIFO)
				sc->sc_stats.ast_rx_fifoerr++;
			if (ds->ds_rxstat.rs_status & HAL_RXERR_PHY) {
				sc->sc_stats.ast_rx_phyerr++;
				phyerr = ds->ds_rxstat.rs_phyerr & 0x1f;
				sc->sc_stats.ast_rx_phy[phyerr]++;

				if (phyerr == HAL_PHYERR_RADAR && ic->ic_opmode == IEEE80211_M_HOSTAP)
				{
					ATH_SCHEDULE_TQUEUE (&sc->sc_radartq, &needmark);
				}

				goto rx_next;
			}
			if (ds->ds_rxstat.rs_status & HAL_RXERR_DECRYPT) {
				/*
				 * Decrypt error.  If the error occurred
				 * because there was no hardware key, then
				 * let the frame through so the upper layers
				 * can process it.  This is necessary for 5210
				 * parts which have no way to setup a ``clear''
				 * key cache entry.
				 *
				 * XXX do key cache faulting
				 */
				if (ds->ds_rxstat.rs_keyix == HAL_RXKEYIX_INVALID)
					goto rx_accept;
				sc->sc_stats.ast_rx_badcrypt++;
			}
			if (ds->ds_rxstat.rs_status & HAL_RXERR_MIC) {
				sc->sc_stats.ast_rx_badmic++;
				/*
				 * Do minimal work required to hand off
				 * the 802.11 header for notifcation.
				 */
				/* XXX frag's and qos frames */
				len = ds->ds_rxstat.rs_datalen;
				if (len >= sizeof (struct ieee80211_frame)) {
					bus_dma_sync_single(sc->sc_bdev,
					    bf->bf_skbaddr, len,
					    BUS_DMA_FROMDEVICE);
					ieee80211_notify_michael_failure(ic,
						(struct ieee80211_frame *) skb->data,
					    sc->sc_splitmic ?
					        ds->ds_rxstat.rs_keyix-32 :
					        ds->ds_rxstat.rs_keyix
					);
				}
			}

			// TODO: correct?
			ic->ic_devstats->rx_errors++;

			/*
			 * accept error frames on the raw device
			 * or in monitor mode if we ask for them.
			 * we'll explicity drop them after capture.
			 */
			if (sc->sc_rxfilter & HAL_RX_FILTER_PHYERR)
				goto rx_accept;

			/*
			 * Reject error frames, we normally don't want
			 * to see them in monitor mode (in monitor mode
			 * allow through packets that have crypto problems).
			 */
			if ((ds->ds_rxstat.rs_status &~
			     (HAL_RXERR_DECRYPT|HAL_RXERR_MIC)) ||
			    sc->sc_ic.ic_opmode != IEEE80211_M_MONITOR)
				goto rx_next;
		}
rx_accept:
		/*
		 * Sync and unmap the frame.  At this point we're
		 * committed to passing the sk_buff somewhere so
		 * clear buf_skb; this means a new sk_buff must be
		 * allocated when the rx descriptor is setup again
		 * to receive another frame.
		 */
		len = ds->ds_rxstat.rs_datalen;
		bus_dma_sync_single(sc->sc_bdev,
			bf->bf_skbaddr, len, BUS_DMA_FROMDEVICE);
		bus_unmap_single(sc->sc_bdev, bf->bf_skbaddr,
			sc->sc_rxbufsize, BUS_DMA_FROMDEVICE);
		bf->bf_skb = NULL;


		sc->sc_stats.ast_ant_rx[ds->ds_rxstat.rs_antenna]++;
		
		if (len < IEEE80211_ACK_LEN) {
			DPRINTF(sc, ATH_DEBUG_RECV,
				"%s: runt packet %d\n", __func__, len);
			sc->sc_stats.ast_rx_tooshort++;
			dev_kfree_skb(skb);
			goto rx_next;
		}

		KASSERT(len <= skb_tailroom(skb), 
			("not enough tailroom (%d vs %d)",
			 len, skb_tailroom(skb)));

		skb_put(skb, len);
		skb->protocol = ETH_P_CONTROL;		/* XXX */

		if (sc->sc_rawdev_enabled && 
		    (sc->sc_rawdev.flags & IFF_UP)) {
			struct sk_buff *skb2;
			skb2 = skb_copy(skb, GFP_ATOMIC);
			if (skb2) {
				ath_rx_capture(&sc->sc_rawdev, ds, skb2);
			}
		}
		
		if (ic->ic_opmode == IEEE80211_M_MONITOR) {
			/*
			 * Monitor mode: discard anything shorter than
			 * an ack or cts, clean the skbuff, fabricate
			 * the Prism header existing tools expect,
			 * and dispatch.
			 */
			/* XXX TSF */

			ath_rx_capture(dev, ds, skb);
			goto rx_next;
		}


		/*
		 * At this point we have no need for error frames
		 * that aren't crypto problems since we're done
		 * with capture.
		 */
		if (ds->ds_rxstat.rs_status &~
		    (HAL_RXERR_DECRYPT|HAL_RXERR_MIC)) {
			dev_kfree_skb(skb);
			goto rx_next;
		}
		/*
		 * From this point on we assume the frame is at least
		 * as large as ieee80211_frame_min; verify that.
		 */
		if (len < IEEE80211_MIN_LEN) {
			DPRINTF(sc, ATH_DEBUG_RECV, "%s: short packet %d\n",
				__func__, len);
			sc->sc_stats.ast_rx_tooshort++;
			dev_kfree_skb(skb);
			goto rx_next;
		}

		/*
		 * Normal receive.
		 */
		if (IFF_DUMPPKTS(sc, ATH_DEBUG_RECV)) {
			ieee80211_dump_pkt(skb->data, len,
				   sc->sc_hwmap[ds->ds_rxstat.rs_rate].ieeerate,
				   ds->ds_rxstat.rs_rssi);
		}

		skb_trim(skb, skb->len - IEEE80211_CRC_LEN);

		/*
		 * Locate the node for sender, track state, and then
		 * pass the (referenced) node up to the 802.11 layer
		 * for its use.
		 */
		ni = ieee80211_find_rxnode(ic,
                        (struct ieee80211_frame_min *)skb->data);

		/*
		 * Track rx rssi and do any rx antenna management.
		 */
		an = ATH_NODE(ni);
		ATH_RSSI_LPF(an->an_avgrssi, ds->ds_rxstat.rs_rssi);
		if (sc->sc_diversity) {
			/*
			 * When using fast diversity, change the default rx
			 * antenna if diversity chooses the other antenna 3
			 * times in a row.
			 */
			if (sc->sc_defant != ds->ds_rxstat.rs_antenna) {
				if (++sc->sc_rxotherant >= 3)
					ath_setdefantenna(sc,
						ds->ds_rxstat.rs_antenna);
			} else
				sc->sc_rxotherant = 0;
		}

		/*
		 * Send frame up for processing.
		 */
		type = ieee80211_input(ic, skb, ni,
			ds->ds_rxstat.rs_rssi, ds->ds_rxstat.rs_tstamp);

		if (sc->sc_softled) {
			/*
			 * Blink for any data frame.  Otherwise do a
			 * heartbeat-style blink when idle.  The latter
			 * is mainly for station mode where we depend on
			 * periodic beacon frames to trigger the poll event.
			 */
			if (type == IEEE80211_FC0_TYPE_DATA) {
				sc->sc_rxrate = ds->ds_rxstat.rs_rate;
				ath_led_event(sc, ATH_LED_RX);
			} else if (jiffies - sc->sc_ledevent >= sc->sc_ledidle)
				ath_led_event(sc, ATH_LED_POLL);
		}

		/*
		 * Reclaim node reference.
		 */
		ieee80211_free_node(ni);
rx_next:
		STAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
	} while (ath_rxbuf_init(sc, bf) == 0);

	/* rx signal state monitoring */
	ath_hal_rxmonitor(ah, &ATH_NODE(ic->ic_bss)->an_halstats);

#undef PA2DESC
}

/*
 * Setup a h/w transmit queue.
 */
static struct ath_txq *
ath_txq_setup(struct ath_softc *sc, int qtype, int subtype)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	struct ath_hal *ah = sc->sc_ah;
	HAL_TXQ_INFO qi;
	int qnum;

	memset(&qi, 0, sizeof(qi));
	qi.tqi_subtype = subtype;
	qi.tqi_aifs = HAL_TXQ_USEDEFAULT;
	qi.tqi_cwmin = HAL_TXQ_USEDEFAULT;
	qi.tqi_cwmax = HAL_TXQ_USEDEFAULT;
	/*
	 * Enable interrupts only for EOL and DESC conditions.
	 * We mark tx descriptors to receive a DESC interrupt
	 * when a tx queue gets deep; otherwise waiting for the
	 * EOL to reap descriptors.  Note that this is done to
	 * reduce interrupt load and this only defers reaping
	 * descriptors, never transmitting frames.  Aside from
	 * reducing interrupts this also permits more concurrency.
	 * The only potential downside is if the tx queue backs
	 * up in which case the top half of the kernel may backup
	 * due to a lack of tx descriptors.
	 */
	qi.tqi_qflags = TXQ_FLAG_TXEOLINT_ENABLE | TXQ_FLAG_TXDESCINT_ENABLE;
#ifdef HAS_CU_SOFTMAC
	// XXX should fix this so that we only jimmy the queue properties
	// when in softmac mode?
	qi.tqi_qflags |= 
	  (TXQ_FLAG_TXOKINT_ENABLE | TXQ_FLAG_TXERRINT_ENABLE | TXQ_FLAG_BACKOFF_DISABLE);
	// Force contention window to be small
	// XXX maybe set this on individual packet queues after setup?
	qi.tqi_cwmin = 1;
	qi.tqi_cwmax = 1;
#endif
	qnum = ath_hal_setuptxqueue(ah, qtype, &qi);
	if (qnum == -1) {
		/*
		 * NB: don't print a message, this happens 
		 * normally on parts with too few tx queues
		 */
		return NULL;
	}
	if (qnum >= N(sc->sc_txq)) {
		printk("%s: hal qnum %u out of range, max %u!\n",
			sc->sc_dev.name, qnum, (unsigned int) N(sc->sc_txq));
		ath_hal_releasetxqueue(ah, qnum);
		return NULL;
	}
	if (!ATH_TXQ_SETUP(sc, qnum)) {
		struct ath_txq *txq = &sc->sc_txq[qnum];

		txq->axq_qnum = qnum;
		txq->axq_depth = 0;
		txq->axq_intrcnt = 0;
		txq->axq_link = NULL;
		STAILQ_INIT(&txq->axq_q);
		ATH_TXQ_LOCK_INIT(sc, txq);
		sc->sc_txqsetup |= 1<<qnum;
	}
	return &sc->sc_txq[qnum];
#undef N
}

/*
 * Setup a hardware data transmit queue for the specified
 * access control.  The hal may not support all requested
 * queues in which case it will return a reference to a
 * previously setup queue.  We record the mapping from ac's
 * to h/w queues for use by ath_tx_start and also track
 * the set of h/w queues being used to optimize work in the
 * transmit interrupt handler and related routines.
 */
static int
ath_tx_setup(struct ath_softc *sc, int ac, int haltype)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	struct ath_txq *txq;

	if (ac >= N(sc->sc_ac2q)) {
		printk("%s: AC %u out of range, max %u!\n",
			sc->sc_dev.name, ac, (unsigned int) N(sc->sc_ac2q));
		return 0;
	}
	txq = ath_txq_setup(sc, HAL_TX_QUEUE_DATA, haltype);
	if (txq != NULL) {
		sc->sc_ac2q[ac] = txq;
		return 1;
	} else
		return 0;
#undef N
}

/*
 * Update WME parameters for a transmit queue.
 */
static int
ath_txq_update(struct ath_softc *sc, int ac)
{
#define	ATH_EXPONENT_TO_VALUE(v)	((1<<v)-1)
#define	ATH_TXOP_TO_US(v)		(v<<5)
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_txq *txq = sc->sc_ac2q[ac];
	struct wmeParams *wmep = &ic->ic_wme.wme_chanParams.cap_wmeParams[ac];
	struct ath_hal *ah = sc->sc_ah;
	HAL_TXQ_INFO qi;

	ath_hal_gettxqueueprops(ah, txq->axq_qnum, &qi);
	qi.tqi_aifs = wmep->wmep_aifsn;
	qi.tqi_cwmin = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmin);
	qi.tqi_cwmax = ATH_EXPONENT_TO_VALUE(wmep->wmep_logcwmax);	
	qi.tqi_burstTime = ATH_TXOP_TO_US(wmep->wmep_txopLimit);

	if (!ath_hal_settxqueueprops(ah, txq->axq_qnum, &qi)) {
		if_printf(&sc->sc_dev, "unable to update hardware queue "
			"parameters for %s traffic!\n",
			ieee80211_wme_acnames[ac]);
		return 0;
	} else {
		ath_hal_resettxqueue(ah, txq->axq_qnum); /* push to h/w */
		return 1;
	}
#undef ATH_TXOP_TO_US
#undef ATH_EXPONENT_TO_VALUE
}

/*
 * Callback from the 802.11 layer to update WME parameters.
 */
static int 
ath_wme_update(struct ieee80211com *ic)
{
	struct ath_softc *sc = ic->ic_dev->priv;

	return !ath_txq_update(sc, WME_AC_BE) ||
	    !ath_txq_update(sc, WME_AC_BK) ||
	    !ath_txq_update(sc, WME_AC_VI) ||
	    !ath_txq_update(sc, WME_AC_VO) ? EIO : 0;
}

/*
 * Reclaim resources for a setup queue.
 */
static void
ath_tx_cleanupq(struct ath_softc *sc, struct ath_txq *txq)
{

	ath_hal_releasetxqueue(sc->sc_ah, txq->axq_qnum);
	ATH_TXQ_LOCK_DESTROY(txq);
	sc->sc_txqsetup &= ~(1<<txq->axq_qnum);
}

/*
 * Reclaim all tx queue resources.
 */
static void
ath_tx_cleanup(struct ath_softc *sc)
{
	int i;

	ATH_LOCK_DESTROY(sc);
	ATH_TXBUF_LOCK_DESTROY(sc);
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_cleanupq(sc, &sc->sc_txq[i]);
	}
}

static int
ath_tx_start(struct net_device *dev, struct ieee80211_node *ni, struct ath_buf *bf,
    struct sk_buff *skb)
{
#define	CTS_DURATION \
	ath_hal_computetxtime(ah, rt, IEEE80211_ACK_LEN, cix, AH_TRUE)
#define	updateCTSForBursting(_ah, _ds, _txq) \
	ath_hal_updateCTSForBursting(_ah, _ds, \
	    _txq->axq_linkbuf != NULL ? _txq->axq_linkbuf->bf_desc : NULL, \
	    _txq->axq_lastdsWithCTS, _txq->axq_gatingds, \
	    txopLimit, CTS_DURATION)
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	const struct chanAccParams *cap = &ic->ic_wme.wme_chanParams;
	int iswep, ismcast, keyix, hdrlen, pktlen, try0;
	u_int8_t rix, txrate, ctsrate;
	u_int8_t cix = 0xff;		/* NB: silence compiler */
	struct ath_desc *ds;
	struct ath_txq *txq;
	struct ieee80211_frame *wh;
	u_int subtype, flags, ctsduration;
	HAL_PKT_TYPE atype;
	const HAL_RATE_TABLE *rt;
	HAL_BOOL shortPreamble;
	struct ath_node *an;
	struct llc *llc;
	int eapol;
	u_int pri;

	wh = (struct ieee80211_frame *) skb->data;
	iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	ismcast = IEEE80211_IS_MULTICAST(wh->i_addr1);
	hdrlen = ieee80211_anyhdrsize(wh);
	// TODO: not so correct (WDS)
	llc = (struct llc *) (skb->data + sizeof(struct ieee80211_frame));
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: ether_type: 0x%x\n",
		__func__, __constant_htons(llc->llc_snap.ether_type));
	if (__constant_htons(llc->llc_snap.ether_type) == ETHERTYPE_PAE)
		eapol = 1;
	else
		eapol = 0;
	llc = NULL;

	/*
	 * Packet length must not include any
	 * pad bytes; deduct them here.
	 */
	//TODO: ??? pktlen = m0->m_pkthdr.len - (hdrlen & 3);
	pktlen = skb->len - (hdrlen & 3);

	if (iswep) {
		const struct ieee80211_cipher *cip;
		struct ieee80211_key *k;

		/*
		 * Construct the 802.11 header+trailer for an encrypted
		 * frame. The only reason this can fail is because of an
		 * unknown or unsupported cipher/key type.
		 */
		k = ieee80211_crypto_encap(ic, ni, skb);
		if (k == NULL) {
			/*
			 * This can happen when the key is yanked after the
			 * frame was queued.  Just discard the frame; the
			 * 802.11 layer counts failures and provides
			 * debugging/diagnostics.
			 */
			dev_kfree_skb(skb);
			return -EIO;
		}
		/*
		 * Adjust the packet + header lengths for the crypto
		 * additions and calculate the h/w key index.  When
		 * a s/w mic is done the frame will have had any mic
		 * added to it prior to entry so skb->len above will
		 * account for it. Otherwise we need to add it to the
		 * packet length.
		 */
		cip = k->wk_cipher;
		hdrlen += cip->ic_header;
		pktlen += cip->ic_header + cip->ic_trailer;
		if ((k->wk_flags & IEEE80211_KEY_SWMIC) == 0)
			pktlen += cip->ic_miclen;
		keyix = k->wk_keyix;

		/* packet header may have moved, reset our local pointer */
		wh = (struct ieee80211_frame *) skb->data;
	} else
		keyix = HAL_TXKEYIX_INVALID;

	pktlen += IEEE80211_CRC_LEN;

	/*
	 * Load the DMA map so any coalescing is done.  This
	 * also calculates the number of descriptors we need.
	 */
	bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
		skb->data, pktlen, BUS_DMA_TODEVICE);
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: skb %p [data %p len %u] skbaddr %lx\n",
		__func__, skb, skb->data, skb->len, (long unsigned int) bf->bf_skbaddr);
	if (BUS_DMA_MAP_ERROR(bf->bf_skbaddr)) {
		if_printf(dev, "%s: DMA mapping failed\n", __func__);
		printk("%s: DMA mapping failed\n", __func__);
		dev_kfree_skb(skb);
		bf->bf_skb = NULL;
		sc->sc_stats.ast_tx_busdma++;
		return -EIO;
	}
	bf->bf_skb = skb;
	bf->bf_node = ni;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = sc->sc_currates;
	KASSERT(rt != NULL, ("no rate table, mode %u", sc->sc_curmode));

	/*
	 * NB: the 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	if ((ic->ic_flags & IEEE80211_F_SHPREAMBLE) &&
	    (ni->ni_capinfo & IEEE80211_CAPINFO_SHORT_PREAMBLE)) {
		shortPreamble = AH_TRUE;
		sc->sc_stats.ast_tx_shortpre++;
	} else {
		shortPreamble = AH_FALSE;
	}
	an = ATH_NODE(ni);
	flags = HAL_TXDESC_CLRDMASK;		/* XXX needed for crypto errs */
	/*
	 * Calculate Atheros packet type from IEEE80211 packet header,
	 * setup for rate calculations, and select h/w transmit queue.
	 */
	switch (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) {
	case IEEE80211_FC0_TYPE_MGT:
		subtype = wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK;
		if (subtype == IEEE80211_FC0_SUBTYPE_BEACON)
			atype = HAL_PKT_TYPE_BEACON;
		else if (subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)
			atype = HAL_PKT_TYPE_PROBE_RESP;
		else if (subtype == IEEE80211_FC0_SUBTYPE_ATIM)
			atype = HAL_PKT_TYPE_ATIM;
		else
			atype = HAL_PKT_TYPE_NORMAL;	/* XXX */
		rix = 0;			/* XXX lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble)
			txrate = an->an_tx_mgtratesp;
		else
			txrate = an->an_tx_mgtrate;
		/* NB: force all management frames to highest queue */
		if (ni->ni_flags & IEEE80211_NODE_QOS) {
			pri = WME_AC_VO;
		} else
			pri = WME_AC_BE;
		flags |= HAL_TXDESC_INTREQ;	/* force interrupt */
		break;
	case IEEE80211_FC0_TYPE_CTL:
		atype = HAL_PKT_TYPE_PSPOLL;	/* stop setting of duration */
		rix = 0;			/* XXX lowest rate */
		try0 = ATH_TXMAXTRY;
		if (shortPreamble)
			txrate = an->an_tx_mgtratesp;
		else
			txrate = an->an_tx_mgtrate;
		/* NB: force all ctl frames to highest queue */
		if (ni->ni_flags & IEEE80211_NODE_QOS) {
			pri = WME_AC_VO;
		} else
			pri = WME_AC_BE;
		flags |= HAL_TXDESC_INTREQ;	/* force interrupt */
		break;
	case IEEE80211_FC0_TYPE_DATA:
		atype = HAL_PKT_TYPE_NORMAL;		/* default */
		if (ismcast) {
			rix = 0;			/* XXX lowest rate */
			try0 = 0;
			if (shortPreamble)
				txrate = an->an_tx_mgtratesp;
			else
				txrate = an->an_tx_mgtrate;
		}
		else if (eapol) {
			rix = 0;			/* XXX lowest rate */
			try0 = 0;			// TODO: userspace or hardware retry?
			if (shortPreamble)
				txrate = an->an_tx_mgtratesp;
			else
				txrate = an->an_tx_mgtrate;
			flags |= HAL_TXDESC_INTREQ;	/* force interrupt */
		} else {
			/*
			 * Data frames; consult the rate control module.
			 */
			ath_rate_findrate(sc, an, shortPreamble, pktlen,
					  &rix, &try0, &txrate);
		}
		sc->sc_txrate = txrate;			/* for LED blinking */
		/*
		 * Default all non-QoS traffic to the background queue.
		 */
		if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
			pri = M_WME_GETAC(skb);
			if (cap->cap_wmeParams[pri].wmep_noackPolicy) {
				flags |= HAL_TXDESC_NOACK;
				sc->sc_stats.ast_tx_noack++;
			}
		} else
			pri = WME_AC_BE;
		break;
	default:
		if_printf(dev, "bogus frame type 0x%x (%s)\n",
			wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK, __func__);
		printk("bogus frame type 0x%x (%s)\n",
		       wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK, __func__);
		/* XXX statistic */
		DPRINTF(sc, ATH_DEBUG_FATAL, "%s: kfree_skb: skb %p [data %p len %u] skbaddr %lx\n",
			__func__, skb, skb->data, skb->len, (long unsigned int) bf->bf_skbaddr);
		dev_kfree_skb(skb);
		bf->bf_skb = NULL;
		return -EIO;
	}
	txq = sc->sc_ac2q[pri];

	/*
	 * When servicing one or more stations in power-save mode
	 * multicast frames must be buffered until after the beacon.
	 * We use the CAB queue for that.
	 */
	if (ismcast && ic->ic_ps_sta) {
		txq = sc->sc_cabq;
		/* XXX? more bit in 802.11 frame header */
	}

	/*
	 * Calculate miscellaneous flags.
	 */
	if (ismcast) {
		flags |= HAL_TXDESC_NOACK;	/* no ack on broad/multicast */
		sc->sc_stats.ast_tx_noack++;
	} else if (pktlen > ic->ic_rtsthreshold) {
		flags |= HAL_TXDESC_RTSENA;	/* RTS based on frame length */
		cix = rt->info[rix].controlRate;
		sc->sc_stats.ast_tx_rts++;
	}

	/*
	 * If 802.11g protection is enabled, determine whether
	 * to use RTS/CTS or just CTS.  Note that this is only
	 * done for OFDM unicast frames.
	 */
	if ((ic->ic_flags & IEEE80211_F_USEPROT) &&
	    rt->info[rix].phy == IEEE80211_T_OFDM &&
	    (flags & HAL_TXDESC_NOACK) == 0) {
		/* XXX fragments must use CCK rates w/ protection */
		if (ic->ic_protmode == IEEE80211_PROT_RTSCTS)
			flags |= HAL_TXDESC_RTSENA;
		else if (ic->ic_protmode == IEEE80211_PROT_CTSONLY)
			flags |= HAL_TXDESC_CTSENA;
		cix = rt->info[sc->sc_protrix].controlRate;
		sc->sc_stats.ast_tx_protect++;
	}

	/*
	 * Calculate duration.  This logically belongs in the 802.11
	 * layer but it lacks sufficient information to calculate it.
	 */
	if ((flags & HAL_TXDESC_NOACK) == 0 &&
	    (wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) != IEEE80211_FC0_TYPE_CTL) {
		u_int16_t dur;
		/*
		 * XXX not right with fragmentation.
		 */
		if (shortPreamble)
			dur = rt->info[rix].spAckDuration;
		else
			dur = rt->info[rix].lpAckDuration;
		*(u_int16_t *)wh->i_dur = htole16(dur);
	}

	/*
	 * Calculate RTS/CTS rate and duration if needed.
	 */
	ctsduration = 0;
	if (flags & (HAL_TXDESC_RTSENA|HAL_TXDESC_CTSENA)) {
		/*
		 * CTS transmit rate is derived from the transmit rate
		 * by looking in the h/w rate table.  We must also factor
		 * in whether or not a short preamble is to be used.
		 */
		/* NB: cix is set above where RTS/CTS is enabled */
		KASSERT(cix != 0xff, ("cix not setup"));
		ctsrate = rt->info[cix].rateCode;
		/*
		 * Compute the transmit duration based on the frame
		 * size and the size of an ACK frame.  We call into the
		 * HAL to do the computation since it depends on the
		 * characteristics of the actual PHY being used.
		 *
		 * NB: CTS is assumed the same size as an ACK so we can
		 *     use the precalculated ACK durations.
		 */
		if (shortPreamble) {
			ctsrate |= rt->info[cix].shortPreamble;
			if (flags & HAL_TXDESC_RTSENA)		/* SIFS + CTS */
				ctsduration += rt->info[cix].spAckDuration;
			ctsduration += ath_hal_computetxtime(ah,
				rt, pktlen, rix, AH_TRUE);
			if ((flags & HAL_TXDESC_NOACK) == 0)	/* SIFS + ACK */
				ctsduration += rt->info[cix].spAckDuration;
		} else {
			if (flags & HAL_TXDESC_RTSENA)		/* SIFS + CTS */
				ctsduration += rt->info[cix].lpAckDuration;
			ctsduration += ath_hal_computetxtime(ah,
				rt, pktlen, rix, AH_FALSE);
			if ((flags & HAL_TXDESC_NOACK) == 0)	/* SIFS + ACK */
				ctsduration += rt->info[cix].lpAckDuration;
		}
		/*
		 * Must disable multi-rate retry when using RTS/CTS.
		 */
		try0 = ATH_TXMAXTRY;
	} else
		ctsrate = 0;

	if (IFF_DUMPPKTS(sc, ATH_DEBUG_XMIT))
		ieee80211_dump_pkt(skb->data, skb->len,
			sc->sc_hwmap[txrate].ieeerate, -1);

	/* 
	 * Determine if a tx interrupt should be generated for
	 * this descriptor.  We take a tx interrupt to reap
	 * descriptors when the h/w hits an EOL condition or
	 * when the descriptor is specifically marked to generate
	 * an interrupt.  We periodically mark descriptors in this
	 * way to insure timely replenishing of the supply needed
	 * for sending frames.  Defering interrupts reduces system
	 * load and potentially allows more concurrent work to be
	 * done but if done to aggressively can cause senders to
	 * backup.
	 *
	 * NB: use >= to deal with sc_txintrperiod changing
	 *     dynamically through sysctl.
	 */
	if (flags & HAL_TXDESC_INTREQ) {
		txq->axq_intrcnt = 0;
	} else if (++txq->axq_intrcnt >= sc->sc_txintrperiod) {
		flags |= HAL_TXDESC_INTREQ;
		txq->axq_intrcnt = 0;
	}

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	/* XXX check return value? */
	ath_hal_setuptxdesc(ah, ds
		, pktlen		/* packet length */
		, hdrlen		/* header length */
		, atype			/* Atheros packet type */
		, ni->ni_txpower	/* txpower */
		, txrate, try0		/* series 0 rate/tries */
		, keyix			/* key cache index */
		, sc->sc_txantenna	/* antenna mode */
		, flags			/* flags */
		, ctsrate		/* rts/cts rate */
		, ctsduration		/* rts/cts duration */
	);
	/*
	 * Setup the multi-rate retry state only when we're
	 * going to use it.  This assumes ath_hal_setuptxdesc
	 * initializes the descriptors (so we don't have to)
	 * when the hardware supports multi-rate retry and
	 * we don't use it.
	 */
	if (try0 != ATH_TXMAXTRY)
		ath_rate_setupxtxdesc(sc, an, ds, shortPreamble, rix);

	/*
	 * Fillin the remainder of the descriptor info.
	 */
	ds->ds_link = 0;
	ds->ds_data = bf->bf_skbaddr;
	ath_hal_filltxdesc(ah, ds
		, skb->len		/* segment length */
		, AH_TRUE		/* first segment */
		, AH_TRUE		/* last segment */
		, ds			/* first descriptor */
	);
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: Q%d: %08x %08x %08x %08x %08x %08x\n",
	    __func__, txq->axq_qnum, ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1, ds->ds_hw[0], ds->ds_hw[1]);
	/*
	 * Insert the frame on the outbound list and
	 * pass it on to the hardware.
	 */
	ATH_TXQ_LOCK_BH(txq);
	if (flags & (HAL_TXDESC_RTSENA | HAL_TXDESC_CTSENA)) {
		u_int32_t txopLimit = IEEE80211_TXOP_TO_US(
			cap->cap_wmeParams[pri].wmep_txopLimit);
		/*
		 * When bursting, potentially extend the CTS duration
		 * of a previously queued frame to cover this frame
		 * and not exceed the txopLimit.  If that can be done
		 * then disable RTS/CTS on this frame since it's now
		 * covered (burst extension).  Otherwise we must terminate
		 * the burst before this frame goes out so as not to
		 * violate the WME parameters.  All this is complicated
		 * as we need to update the state of packets on the
		 * (live) hardware queue.  The logic is buried in the hal
		 * because it's highly chip-specific.
		 */
		if (txopLimit != 0) {
			sc->sc_stats.ast_tx_ctsburst++;
			if (updateCTSForBursting(ah, ds, txq) == 0) {
				/*
				 * This frame was not covered by RTS/CTS from
				 * the previous frame in the burst; update the
				 * descriptor pointers so this frame is now
				 * treated as the last frame for extending a
				 * burst.
				 */
				txq->axq_lastdsWithCTS = ds;
				/* set gating Desc to final desc */
				txq->axq_gatingds =
					(struct ath_desc *)txq->axq_link;
			} else
				sc->sc_stats.ast_tx_ctsext++;
		}
	}
	ATH_TXQ_INSERT_TAIL(txq, bf, bf_list);
	DPRINTF(sc, ATH_DEBUG_TX_PROC, "%s: txq depth = %d\n",
		__func__, txq->axq_depth);
	if (txq->axq_link == NULL) {
		ath_hal_puttxbuf(ah, txq->axq_qnum, bf->bf_daddr);
		DPRINTF(sc, ATH_DEBUG_XMIT,
			"%s: TXDP[%u] = %p (%p) depth %d\n", __func__,
			txq->axq_qnum, (caddr_t)bf->bf_daddr, bf->bf_desc,
			txq->axq_depth);
	} else {
		*txq->axq_link = bf->bf_daddr;
		DPRINTF(sc, ATH_DEBUG_XMIT,
			"%s: link[%u](%p)=%p (%p) depth %d\n", __func__,
			txq->axq_qnum, txq->axq_link,
			(caddr_t)bf->bf_daddr, bf->bf_desc, txq->axq_depth);
	}
	txq->axq_link = &bf->bf_desc->ds_link;
	/*
	 * The CAB queue is started from the SWBA handler since
	 * frames only go out on DTIM and to avoid possible races.
	 */
	if (txq != sc->sc_cabq)
		ath_hal_txstart(ah, txq->axq_qnum);
	ATH_TXQ_UNLOCK_BH(txq);

	dev->trans_start = jiffies;
	sc->sc_rawdev.trans_start = jiffies;
	return 0;
#undef updateCTSForBursting
#undef CTS_DURATION
}

/*
 * Process completed xmit descriptors from the specified queue.
 */
static void
ath_tx_processq(struct ath_softc *sc, struct ath_txq *txq)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_buf *bf;
	struct ath_desc *ds;
	struct ieee80211_node *ni;
	struct ath_node *an;
	int sr, lr, pri;
	HAL_STATUS status;

	DPRINTF(sc, ATH_DEBUG_TX_PROC, "%s: tx queue %u head %p link %p\n",
		__func__, txq->axq_qnum,
		(caddr_t)(uintptr_t) ath_hal_gettxbuf(sc->sc_ah, txq->axq_qnum),
		txq->axq_link);
	for (;;) {
		ATH_TXQ_LOCK(txq);
		txq->axq_intrcnt = 0;	/* reset periodic desc intr count */
		bf = STAILQ_FIRST(&txq->axq_q);
		if (bf == NULL) {
			txq->axq_link = NULL;
			ATH_TXQ_UNLOCK(txq);
			break;
		}
		ds = bf->bf_desc;		/* NB: last decriptor */
		status = ath_hal_txprocdesc(ah, ds);
#ifdef AR_DEBUG
		if (sc->sc_debug & ATH_DEBUG_XMIT_DESC)
			ath_printtxbuf(bf, status == HAL_OK);
#endif
		if (status == HAL_EINPROGRESS) {
			ATH_TXQ_UNLOCK(txq);
			break;
		}
		if (ds == txq->axq_lastdsWithCTS)
			txq->axq_lastdsWithCTS = NULL;
		if (ds == txq->axq_gatingds)
			txq->axq_gatingds = NULL;
		ATH_TXQ_REMOVE_HEAD(txq, bf_list);
		ATH_TXQ_UNLOCK(txq);

		ni = bf->bf_node;
		if (ni != NULL) {
			an = ATH_NODE(ni);
			if (ds->ds_txstat.ts_status == 0) {
				u_int8_t txant = ds->ds_txstat.ts_antenna;
				sc->sc_stats.ast_ant_tx[txant]++;
				sc->sc_ant_tx[txant]++;
				if (ds->ds_txstat.ts_rate & HAL_TXSTAT_ALTRATE)
					sc->sc_stats.ast_tx_altrate++;
				sc->sc_stats.ast_tx_rssi =
					ds->ds_txstat.ts_rssi;
				ATH_RSSI_LPF(an->an_halstats.ns_avgtxrssi,
					ds->ds_txstat.ts_rssi);
				pri = M_WME_GETAC(bf->bf_skb);
				if (pri >= WME_AC_VO)
					ic->ic_wme.wme_hipri_traffic++;
				ni->ni_inact = ni->ni_inact_reload;
			} else {
				if (ds->ds_txstat.ts_status & HAL_TXERR_XRETRY)
					sc->sc_stats.ast_tx_xretries++;
				if (ds->ds_txstat.ts_status & HAL_TXERR_FIFO)
					sc->sc_stats.ast_tx_fifoerr++;
				if (ds->ds_txstat.ts_status & HAL_TXERR_FILT)
					sc->sc_stats.ast_tx_filtered++;
			}
			sr = ds->ds_txstat.ts_shortretry;
			lr = ds->ds_txstat.ts_longretry;
			sc->sc_stats.ast_tx_shortretry += sr;
			sc->sc_stats.ast_tx_longretry += lr;
			/*
			 * Hand the descriptor to the rate control algorithm.
			 */
			ath_rate_tx_complete(sc, an, ds);
			/*
			 * Reclaim reference to node.
			 *
			 * NB: the node may be reclaimed here if, for example
			 *     this is a DEAUTH message that was sent and the
			 *     node was timed out due to inactivity.
			 */
			ieee80211_free_node(ni);
		}
		bus_unmap_single(sc->sc_bdev,
			bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);

		if (sc->sc_rawdev_enabled) {
			ath_tx_capture(&sc->sc_rawdev, ds, bf->bf_skb);
		} else {
			dev_kfree_skb(bf->bf_skb);
		}
		bf->bf_skb = NULL;
		bf->bf_node = NULL;

		ATH_TXBUF_LOCK(sc);
		STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
		ATH_TXBUF_UNLOCK(sc);
	}
}

/*
 * Deferred processing of transmit interrupt; special-cased
 * for a single hardware transmit queue (e.g. 5210 and 5211).
 */
static void
ath_tx_tasklet_q0(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

#ifdef HAS_CU_SOFTMAC
	if ((sc->sc_cu_softmac) /*&&
	    (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR*/) {
	  ath_cu_softmac_txdone_tasklet(data);
	  return;
	}
#endif

	ath_tx_processq(sc, &sc->sc_txq[0]);
	ath_tx_processq(sc, sc->sc_cabq);

	sc->sc_tx_timer = 0;

	if (sc->sc_softled)
		ath_led_event(sc, ATH_LED_TX);

        // TODO: okay???
	/*
	 * Don't wakeup unless we're associated; this insures we don't
	 * signal the upper layer it's ok to start sending data frames.
	 */
	/* XXX use a low watermark to reduce wakeups */
	if (ic->ic_state == IEEE80211_S_RUN)
		netif_wake_queue(dev);

	if (sc->sc_rawdev_enabled)
		netif_wake_queue(&sc->sc_rawdev);
}

/*
 * Deferred processing of transmit interrupt; special-cased
 * for four hardware queues, 0-3 (e.g. 5212 w/ WME support).
 */
static void
ath_tx_tasklet_q0123(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

#ifdef HAS_CU_SOFTMAC
	if ((sc->sc_cu_softmac) /*&&
	    (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR)*/) {
	  ath_cu_softmac_txdone_tasklet(data);
	  return;
	}
#endif

	/*
	 * Process each active queue.
	 */
	ath_tx_processq(sc, &sc->sc_txq[0]);
	ath_tx_processq(sc, &sc->sc_txq[1]);
	ath_tx_processq(sc, &sc->sc_txq[2]);
	ath_tx_processq(sc, &sc->sc_txq[3]);
	ath_tx_processq(sc, sc->sc_cabq);

	sc->sc_tx_timer = 0;

	if (sc->sc_softled)
		ath_led_event(sc, ATH_LED_TX);

        // TODO: okay???
	/*
	 * Don't wakeup unless we're associated; this insures we don't
	 * signal the upper layer it's ok to start sending data frames.
	 */
	/* XXX use a low watermark to reduce wakeups */
	if (ic->ic_state == IEEE80211_S_RUN)
		netif_wake_queue(dev);

	if (sc->sc_rawdev_enabled)
		netif_wake_queue(&sc->sc_rawdev);
}

/*
 * Deferred processing of transmit interrupt.
 */
static void
ath_tx_tasklet(TQUEUE_ARG data)
{
	struct net_device *dev = (struct net_device *)data;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	int i;

#ifdef HAS_CU_SOFTMAC
	if ((sc->sc_cu_softmac) /*&&
	    (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR)*/) {
	  ath_cu_softmac_txdone_tasklet(data);
	  return;
	}
#endif

	/*
	 * Process each active queue.
	 */
	/* XXX faster to read ISR_S0_S and ISR_S1_S to determine q's? */
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_processq(sc, &sc->sc_txq[i]);
	}

	sc->sc_tx_timer = 0;

	if (sc->sc_softled)
		ath_led_event(sc, ATH_LED_TX);

        // TODO: okay???
	/*
	 * Don't wakeup unless we're associated; this insures we don't
	 * signal the upper layer it's ok to start sending data frames.
	 */
	/* XXX use a low watermark to reduce wakeups */
	if (ic->ic_state == IEEE80211_S_RUN)
		netif_wake_queue(dev);

	if (sc->sc_rawdev_enabled)
		netif_wake_queue(&sc->sc_rawdev);

}

static void
ath_tx_timeout(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	sc->sc_stats.ast_watchdog++;
	ath_init(dev);
}

static void
ath_tx_draintxq(struct ath_softc *sc, struct ath_txq *txq)
{
#ifdef AR_DEBUG
	struct ath_hal *ah = sc->sc_ah;
#endif
	struct ieee80211_node *ni;
	struct ath_buf *bf;

	/*
	 * NB: this assumes output has been stopped and
	 *     we do not need to block ath_tx_tasklet
	 */
	for (;;) {
		ATH_TXQ_LOCK_BH(txq);
		bf = STAILQ_FIRST(&txq->axq_q);
		if (bf == NULL) {
			txq->axq_link = NULL;
			ATH_TXQ_UNLOCK_BH(txq);
			break;
		}
		ATH_TXQ_REMOVE_HEAD(txq, bf_list);
		ATH_TXQ_UNLOCK_BH(txq);
#ifdef AR_DEBUG
		if (sc->sc_debug & ATH_DEBUG_RESET)
			ath_printtxbuf(bf,
				ath_hal_txprocdesc(ah, bf->bf_desc) == HAL_OK);
#endif /* AR_DEBUG */
		bus_unmap_single(sc->sc_bdev,
			bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);
		dev_kfree_skb(bf->bf_skb);
		bf->bf_skb = NULL;
		ni = bf->bf_node;
		bf->bf_node = NULL;
		if (ni != NULL) {
			/*
			 * Reclaim node reference.
			 */
			ieee80211_free_node(ni);
		}
		ATH_TXBUF_LOCK_BH(sc);
		STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
		ATH_TXBUF_UNLOCK_BH(sc);
	}
}

static void
ath_tx_stopdma(struct ath_softc *sc, struct ath_txq *txq)
{
	struct ath_hal *ah = sc->sc_ah;

	(void) ath_hal_stoptxdma(ah, txq->axq_qnum);
	DPRINTF(sc, ATH_DEBUG_RESET, "%s: tx queue [%u] %p, link %p\n",
	    __func__, txq->axq_qnum,
	    (caddr_t)(uintptr_t) ath_hal_gettxbuf(ah, txq->axq_qnum),
	    txq->axq_link);
}

/*
 * Drain the transmit queues and reclaim resources.
 */
static void
ath_draintxq(struct ath_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	int i;

	/* XXX return value */
	if (!sc->sc_invalid) {
		/* don't touch the hardware if marked invalid */
		(void) ath_hal_stoptxdma(ah, sc->sc_bhalq);
		DPRINTF(sc, ATH_DEBUG_RESET,
		    "%s: beacon queue %p\n", __func__,
		    (caddr_t)(uintptr_t) ath_hal_gettxbuf(ah, sc->sc_bhalq));
		for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
			if (ATH_TXQ_SETUP(sc, i))
				ath_tx_stopdma(sc, &sc->sc_txq[i]);
		}
	}
	sc->sc_dev.trans_start = jiffies;
	sc->sc_rawdev.trans_start = jiffies;
	
	netif_start_queue(&sc->sc_dev);		// TODO: needed here?
	if (sc->sc_rawdev_enabled)
		netif_start_queue(&sc->sc_rawdev);
	
	for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
		if (ATH_TXQ_SETUP(sc, i))
			ath_tx_draintxq(sc, &sc->sc_txq[i]);
	}
	sc->sc_tx_timer = 0;
}

/*
 * Disable the receive h/w in preparation for a reset.
 */
static void
ath_stoprecv(struct ath_softc *sc)
{
#define	PA2DESC(_sc, _pa) \
	((struct ath_desc *)((caddr_t)(_sc)->sc_desc + \
		((_pa) - (_sc)->sc_desc_daddr)))
	struct ath_hal *ah = sc->sc_ah;

	ath_hal_stoppcurecv(ah);	/* disable PCU */
	ath_hal_setrxfilter(ah, 0);	/* clear recv filter */
	ath_hal_stopdmarecv(ah);	/* disable DMA engine */
	mdelay(3);			/* 3ms is long enough for 1 frame */
#ifdef AR_DEBUG
	if (sc->sc_debug & (ATH_DEBUG_RESET | ATH_DEBUG_FATAL)) {	// TODO: compiler warns integer overflow
		struct ath_buf *bf;

		printk("%s: rx queue %p, link %p\n", __func__,
			(caddr_t)(uintptr_t) ath_hal_getrxbuf(ah), sc->sc_rxlink);
		STAILQ_FOREACH(bf, &sc->sc_rxbuf, bf_list) {
			struct ath_desc *ds = bf->bf_desc;
			HAL_STATUS status = ath_hal_rxprocdesc(ah, ds,
				bf->bf_daddr, PA2DESC(sc, ds->ds_link));
			if (status == HAL_OK || (sc->sc_debug & ATH_DEBUG_FATAL))
				ath_printrxbuf(bf, status == HAL_OK);
		}
	}
#endif
	sc->sc_rxlink = NULL;		/* just in case */
#undef PA2DESC
}

/*
 * Enable the receive h/w following a reset.
 */
static int
ath_startrecv(struct ath_softc *sc)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	struct net_device *dev = ic->ic_dev;
	struct ath_buf *bf;

	/*
	 * Cisco's VPN software requires that drivers be able to
	 * receive encapsulated frames that are larger than the MTU.
	 * Since we can't be sure how large a frame we'll get, setup
	 * to handle the larges on possible.  If you're not using the
	 * VPN driver and want to save memory, define ATH_ENFORCE_MTU
	 * and you'll allocate only what you really need.
	 */
#ifdef ATH_ENFORCE_MTU
	if (sc->sc_ic.ic_opmode == IEEE80211_M_MONITOR) {
		sc->sc_rxbufsize = roundup(IEEE80211_MAX_LEN, sc->sc_cachelsz);
	} else {
		sc->sc_rxbufsize = roundup(sizeof(struct ieee80211_frame) +
			dev->mtu + IEEE80211_CRC_LEN +
			(IEEE80211_WEP_IVLEN + IEEE80211_WEP_KIDLEN +
			 IEEE80211_WEP_CRCLEN), sc->sc_cachelsz);
	}
#else
	sc->sc_rxbufsize = roundup(IEEE80211_MAX_LEN, sc->sc_cachelsz);
#endif
	DPRINTF(sc, ATH_DEBUG_RESET, "%s: mtu %u cachelsz %u rxbufsize %u\n",
		__func__, dev->mtu, sc->sc_cachelsz, sc->sc_rxbufsize);

	sc->sc_rxlink = NULL;
	STAILQ_FOREACH(bf, &sc->sc_rxbuf, bf_list) {
		int error = ath_rxbuf_init(sc, bf);
		if (error != 0) {
			DPRINTF(sc, ATH_DEBUG_RECV,
				"%s: ath_rxbuf_init failed %d\n",
				__func__, error);
			return error;
		}
	}

	bf = STAILQ_FIRST(&sc->sc_rxbuf);
	ath_hal_putrxbuf(ah, bf->bf_daddr);
	ath_hal_rxena(ah);		/* enable recv descriptors */
	ath_mode_init(dev);		/* set filters, etc. */
	ath_hal_startpcurecv(ah);	/* re-enable PCU/DMA engine */
	return 0;
}

/* 
 * Update internal state after a channel change.
 */
static void
ath_chan_change(struct ath_softc *sc, struct ieee80211_channel *chan)
{
	struct ieee80211com *ic = &sc->sc_ic;
	enum ieee80211_phymode mode;
	u_int16_t flags;

	/*
	 * Change channels and update the h/w rate map
	 * if we're switching; e.g. 11a to 11b/g.
	 */
	mode = ieee80211_chan2mode(ic, chan);
	if (mode != sc->sc_curmode)
		ath_setcurmode(sc, mode);
	/*
	 * Update BPF state.  NB: ethereal et. al. don't handle
	 * merged flags well so pick a unique mode for their use.
	 */
	if (IEEE80211_IS_CHAN_A(chan))
		flags = IEEE80211_CHAN_A;
	/* XXX 11g schizophrenia */
	else if (IEEE80211_IS_CHAN_G(chan) ||
	    IEEE80211_IS_CHAN_PUREG(chan))
		flags = IEEE80211_CHAN_G;
	else
		flags = IEEE80211_CHAN_B;
	if (IEEE80211_IS_CHAN_T(chan))
		flags |= IEEE80211_CHAN_TURBO;
}

/*
 * Set/change channels.  If the channel is really being changed,
 * it's done by reseting the chip.  To accomplish this we must
 * first cleanup any pending DMA, then restart stuff after a la
 * ath_init.
 */
static int
ath_chan_set(struct ath_softc *sc, struct ieee80211_channel *chan)
{
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	HAL_CHANNEL hchan;

	/*
	 * Convert to a HAL channel description with
	 * the flags constrained to reflect the current
	 * operating mode.
	 */
	if (chan == IEEE80211_CHAN_ANYC) {
		return 0;
	}
	hchan.channel = chan->ic_freq;
	hchan.channelFlags = ath_chan2flags(ic, chan);

	DPRINTF(sc, ATH_DEBUG_RESET, "%s: %u (%u MHz) -> %u (%u MHz)\n",
	    __func__,
	    ath_hal_mhz2ieee(sc->sc_curchan.channel,
		sc->sc_curchan.channelFlags),
	    	sc->sc_curchan.channel,
	    ath_hal_mhz2ieee(hchan.channel, hchan.channelFlags), hchan.channel);
	if (hchan.channel != sc->sc_curchan.channel ||
	    hchan.channelFlags != sc->sc_curchan.channelFlags) {
		HAL_STATUS status;

		/*
		 * To switch channels clear any pending DMA operations;
		 * wait long enough for the RX fifo to drain, reset the
		 * hardware at the new frequency, and then re-enable
		 * the relevant bits of the h/w.
		 */
		ath_hal_intrset(ah, 0);		/* disable interrupts */
		ath_draintxq(sc);		/* clear pending tx frames */
		ath_stoprecv(sc);		/* turn off frame recv */
#ifdef HAS_CU_SOFTMAC
		if (!ath_hal_reset(ah, IEEE80211_M_MONITOR, &hchan, AH_TRUE, &status)) {
#else
		if (!ath_hal_reset(ah, ic->ic_opmode, &hchan, AH_TRUE, &status)) {
#endif
			if_printf(ic->ic_dev, "ath_chan_set: unable to reset "
				"channel %u (%u Mhz)\n",
				ieee80211_chan2ieee(ic, chan), chan->ic_freq);
			return EIO;
		}
		sc->sc_curchan = hchan;
		ath_update_txpow(sc);		/* update tx power state */

		/*
		 * Re-enable rx framework.
		 */
		if (ath_startrecv(sc) != 0) {
			if_printf(ic->ic_dev,
				"ath_chan_set: unable to restart recv logic\n");
			return EIO;
		}

		/*
		 * Change channels and update the h/w rate map
		 * if we're switching; e.g. 11a to 11b/g.
		 */
		ic->ic_ibss_chan = chan;
		ath_chan_change(sc, chan);

		/*
		 * Re-enable interrupts.
		 */
		ath_hal_intrset(ah, sc->sc_imask);
	}
	return 0;
}

static void
ath_next_scan(unsigned long arg)
{
	struct net_device *dev = (struct net_device *) arg;
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

	if (ic->ic_state == IEEE80211_S_SCAN)
		ieee80211_next_scan(ic);
}

/*
 * Periodically recalibrate the PHY to account
 * for temperature/environment changes.
 */
static void
ath_calibrate(unsigned long arg)
{
	struct net_device *dev = (struct net_device *) arg;
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;

#ifdef HAS_CU_SOFTMAC
	if (!sc->sc_cu_softmac_noautocalibrate) {
#endif
	sc->sc_stats.ast_per_cal++;

	DPRINTF(sc, ATH_DEBUG_CALIBRATE, "%s: channel %u/%x\n",
		__func__, sc->sc_curchan.channel, sc->sc_curchan.channelFlags);

	if (ath_hal_getrfgain(ah) == HAL_RFGAIN_NEED_CHANGE) {
		/*
		 * Rfgain is out of bounds, reset the chip
		 * to load new gain values.
		 */
		sc->sc_stats.ast_per_rfgain++;
		ath_reset(dev);
	}
	if (!ath_hal_calibrate(ah, &sc->sc_curchan)) {
		DPRINTF(sc, ATH_DEBUG_ANY,
			"%s: calibration of channel %u failed\n",
			__func__, sc->sc_curchan.channel);
		sc->sc_stats.ast_per_calfail++;
	}
#ifdef HAS_CU_SOFTMAC
	}
#endif
	sc->sc_cal_ch.expires = jiffies + (ath_calinterval * HZ);
	add_timer(&sc->sc_cal_ch);
}

#ifdef HAS_CU_SOFTMAC
/*
 * Immediately recalibrate the PHY to account
 * for temperature/environment changes.
 */
static void
ath_calibrate_now(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;

	sc->sc_stats.ast_per_cal++;

	DPRINTF(sc, ATH_DEBUG_CALIBRATE, "%s: channel %u/%x\n",
		__func__, sc->sc_curchan.channel, sc->sc_curchan.channelFlags);

	if (ath_hal_getrfgain(ah) == HAL_RFGAIN_NEED_CHANGE) {
		/*
		 * Rfgain is out of bounds, reset the chip
		 * to load new gain values.
		 */
		sc->sc_stats.ast_per_rfgain++;
		ath_reset(dev);
	}
	if (!ath_hal_calibrate(ah, &sc->sc_curchan)) {
		DPRINTF(sc, ATH_DEBUG_ANY,
			"%s: calibration of channel %u failed\n",
			__func__, sc->sc_curchan.channel);
		sc->sc_stats.ast_per_calfail++;
	}
}
#endif

static int
ath_newstate(struct ieee80211com *ic, enum ieee80211_state nstate, int arg)
{
	struct net_device *dev = ic->ic_dev;
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211_node *ni;
	int i, error;
	const u_int8_t *bssid;
	u_int32_t rfilt;
	static const HAL_LED_STATE leds[] = {
	    HAL_LED_INIT,	/* IEEE80211_S_INIT */
	    HAL_LED_SCAN,	/* IEEE80211_S_SCAN */
	    HAL_LED_AUTH,	/* IEEE80211_S_AUTH */
	    HAL_LED_ASSOC, 	/* IEEE80211_S_ASSOC */
	    HAL_LED_RUN, 	/* IEEE80211_S_RUN */
	};

	DPRINTF(sc, ATH_DEBUG_STATE, "%s: %s -> %s\n", __func__,
		ieee80211_state_name[ic->ic_state],
		ieee80211_state_name[nstate]);

	del_timer(&sc->sc_scan_ch);		/* ap/neighbor scan timer */
	del_timer(&sc->sc_cal_ch);		/* periodic calibration timer */
	ath_hal_setledstate(ah, leds[nstate]);	/* set LED */
	netif_stop_queue(dev);			/* before we do anything else */
	if (sc->sc_rawdev_enabled)
		netif_stop_queue(&sc->sc_rawdev);

	if (nstate == IEEE80211_S_INIT) {
		sc->sc_imask &= ~(HAL_INT_SWBA | HAL_INT_BMISS);
		/*
		 * NB: disable interrupts so we don't rx frames.
		 */
		ath_hal_intrset(ah, sc->sc_imask &~ ~HAL_INT_GLOBAL);	// TODO: compiler warns integer overflow
		/*
		 * Notify the rate control algorithm.
		 */
		ath_rate_newstate(sc, nstate);
		goto done;
	}
	ni = ic->ic_bss;
	error = ath_chan_set(sc, ni->ni_chan);
	if (error != 0)
		goto bad;
	rfilt = ath_calcrxfilter(sc, nstate);
	if (nstate == IEEE80211_S_SCAN)
		bssid = dev->broadcast;
	else
		bssid = ni->ni_bssid;
	ath_hal_setrxfilter(ah, rfilt);
	DPRINTF(sc, ATH_DEBUG_STATE, "%s: RX filter 0x%x bssid %s\n",
		 __func__, rfilt, ether_sprintf(bssid));

	if (nstate == IEEE80211_S_RUN && ic->ic_opmode == IEEE80211_M_STA)
		ath_hal_setassocid(ah, bssid, ni->ni_associd);
	else
		ath_hal_setassocid(ah, bssid, 0);
	if (ic->ic_flags & IEEE80211_F_PRIVACY) {
		for (i = 0; i < IEEE80211_WEP_NKID; i++)
			if (ath_hal_keyisvalid(ah, i))
				ath_hal_keysetmac(ah, i, bssid);
	}

	/*
	 * Notify the rate control algorithm so rates
	 * are setup should ath_beacon_alloc be called.
	 */
	ath_rate_newstate(sc, nstate);

	if (ic->ic_opmode == IEEE80211_M_MONITOR) {
		/* nothing to do */;
	} else if (nstate == IEEE80211_S_RUN) {
		DPRINTF(sc, ATH_DEBUG_STATE,
			"%s(RUN): ic_flags=0x%08x iv=%d bssid=%s "
			"capinfo=0x%04x chan=%d\n"
			 , __func__
			 , ic->ic_flags
			 , ni->ni_intval
			 , ether_sprintf(ni->ni_bssid)
			 , ni->ni_capinfo
			 , ieee80211_chan2ieee(ic, ni->ni_chan));

		/*
		 * Allocate and setup the beacon frame for AP or adhoc mode.
		 */
		if (ic->ic_opmode == IEEE80211_M_HOSTAP ||
		    ic->ic_opmode == IEEE80211_M_IBSS) {
			/*
			 * Stop any previous beacon DMA.  This may be
			 * necessary, for example, when an ibss merge
			 * causes reconfiguration; there will be a state
			 * transition from RUN->RUN that means we may
			 * be called with beacon transmission active.
			 */
			ath_hal_stoptxdma(ah, sc->sc_bhalq);
			ath_beacon_free(sc);
			error = ath_beacon_alloc(sc, ni);
			if (error != 0)
				goto bad;
		}

		/*
		 * Configure the beacon and sleep timers.
		 */
		ath_beacon_config(sc);
	} else {
		ath_hal_intrset(ah,
			sc->sc_imask &~ (HAL_INT_SWBA | HAL_INT_BMISS));
		sc->sc_imask &= ~(HAL_INT_SWBA | HAL_INT_BMISS);
	}
done:
	/*
	 * Invoke the parent method to complete the work.
	 */
	error = sc->sc_newstate(ic, nstate, arg);
	/*
	 * Finally, start any timers.
	 */
	if (nstate == IEEE80211_S_RUN) {
		/* start periodic recalibration timer */
		mod_timer(&sc->sc_cal_ch, jiffies + (ath_calinterval * HZ));
	} else if (nstate == IEEE80211_S_SCAN) {
		/* start ap/neighbor scan timer */
		mod_timer(&sc->sc_scan_ch,
			jiffies + ((HZ * ath_dwelltime) / 1000));
	}
bad:
	netif_start_queue(dev);
	if (sc->sc_rawdev_enabled) 
		netif_start_queue(&sc->sc_rawdev);

	return error;
}

/*
 * Setup driver-specific state for a newly associated node.
 * Note that we're called also on a re-associate, the isnew
 * param tells us if this is the first time or not.
 */
static void
ath_newassoc(struct ieee80211com *ic, struct ieee80211_node *ni, int isnew)
{
	struct ath_softc *sc = ic->ic_dev->priv;

	ath_rate_newassoc(sc, ATH_NODE(ni), isnew);
}

static int
ath_getchannels(struct net_device *dev, u_int cc,
	HAL_BOOL outdoor, HAL_BOOL xchanmode)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	HAL_CHANNEL *chans;
	int i, ix, nchan;

	chans = kmalloc(IEEE80211_CHAN_MAX * sizeof(HAL_CHANNEL), GFP_KERNEL);
	if (chans == NULL) {
		if_printf(dev, "unable to allocate channel table\n");
		return ENOMEM;
	}
	if (!ath_hal_init_channels(ah, chans, IEEE80211_CHAN_MAX, &nchan,
	    cc, HAL_MODE_ALL, outdoor, xchanmode)) {
		u_int32_t rd;

		ath_hal_getregdomain(ah, &rd);
		if_printf(dev, "unable to collect channel list from hal; "
			"regdomain likely %u country code %u\n", rd, cc);
		kfree(chans);
		return EINVAL;
	}

	/*
	 * Convert HAL channels to ieee80211 ones and insert
	 * them in the table according to their channel number.
	 */
	for (i = 0; i < nchan; i++) {
		HAL_CHANNEL *c = &chans[i];
		ix = ath_hal_mhz2ieee(c->channel, c->channelFlags);
		if (ix > IEEE80211_CHAN_MAX) {
			if_printf(dev, "bad hal channel %u (%u/%x) ignored\n",
				ix, c->channel, c->channelFlags);
			continue;
		}
		/* NB: flags are known to be compatible */
		if (ic->ic_channels[ix].ic_freq == 0) {
			ic->ic_channels[ix].ic_freq = c->channel;
			ic->ic_channels[ix].ic_flags = c->channelFlags;
		} else {
			/* channels overlap; e.g. 11g and 11b */
			ic->ic_channels[ix].ic_flags |= c->channelFlags;
		}
	}
	kfree(chans);
	return 0;
}

/*
 * Turn the LED off: flip the pin and then set a timer so no
 * update will happen for the specified duration.
 */
static void
ath_led_off(unsigned long arg)
{
	struct ath_softc *sc = (struct ath_softc *) arg;
        
        if(sc->sc_endblink == 1){
            /* part of ath_led_done() */
            sc->sc_blinking = 0;
        } else{
            ath_hal_gpioset(sc->sc_ah, sc->sc_ledpin, !sc->sc_ledon);
            sc->sc_endblink = 1;
            mod_timer(&sc->sc_ledtimer, jiffies + sc->sc_ledoff);
        }
}

/*
 * Blink the LED according to the specified on/off times.
 */
static void
ath_led_blink(struct ath_softc *sc, int on, int off)
{
	DPRINTF(sc, ATH_DEBUG_LED, "%s: on %u off %u\n", __func__, on, off);
	ath_hal_gpioset(sc->sc_ah, sc->sc_ledpin, sc->sc_ledon);
	sc->sc_blinking = 1;
	sc->sc_endblink = 0;
	sc->sc_ledoff = off;
	mod_timer(&sc->sc_ledtimer, jiffies + on);
}

static void
ath_led_event(struct ath_softc *sc, int event)
{

	sc->sc_ledevent = jiffies;	/* time of last event */
	if (sc->sc_blinking)		/* don't interrupt active blink */
		return;
	switch (event) {
	case ATH_LED_POLL:
		ath_led_blink(sc, sc->sc_hwmap[0].ledon,
			sc->sc_hwmap[0].ledoff);
		break;
	case ATH_LED_TX:
		ath_led_blink(sc, sc->sc_hwmap[sc->sc_txrate].ledon,
			sc->sc_hwmap[sc->sc_txrate].ledoff);
		break;
	case ATH_LED_RX:
		ath_led_blink(sc, sc->sc_hwmap[sc->sc_rxrate].ledon,
			sc->sc_hwmap[sc->sc_rxrate].ledoff);
		break;
	}
}

static void
ath_update_txpow(struct ath_softc *sc)
{
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	u_int32_t txpow;

	if (sc->sc_curtxpow != ic->ic_txpowlimit) {
		ath_hal_settxpowlimit(ah, ic->ic_txpowlimit);
		/* read back in case value is clamped */
		ath_hal_gettxpowlimit(ah, &txpow);
		ic->ic_txpowlimit = sc->sc_curtxpow = txpow;
	}
	/* 
	 * Fetch max tx power level for status requests.
	 */
	ath_hal_getmaxtxpow(sc->sc_ah, &txpow);
	ic->ic_bss->ni_txpower = txpow;
}

static int
ath_rate_setup(struct net_device *dev, u_int mode)
{
	struct ath_softc *sc = dev->priv;
	struct ath_hal *ah = sc->sc_ah;
	struct ieee80211com *ic = &sc->sc_ic;
	const HAL_RATE_TABLE *rt;
	struct ieee80211_rateset *rs;
	int i, maxrates;

	switch (mode) {
	case IEEE80211_MODE_11A:
		sc->sc_rates[mode] = ath_hal_getratetable(ah, HAL_MODE_11A);
		break;
	case IEEE80211_MODE_11B:
		sc->sc_rates[mode] = ath_hal_getratetable(ah, HAL_MODE_11B);
		break;
	case IEEE80211_MODE_11G:
		sc->sc_rates[mode] = ath_hal_getratetable(ah, HAL_MODE_11G);
		break;
	case IEEE80211_MODE_TURBO_A:
		sc->sc_rates[mode] = ath_hal_getratetable(ah, HAL_MODE_TURBO);
		break;
	case IEEE80211_MODE_TURBO_G:
		sc->sc_rates[mode] = ath_hal_getratetable(ah, HAL_MODE_108G);
		break;
	default:
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: invalid mode %u\n",
			__func__, mode);
		return 0;
	}
	rt = sc->sc_rates[mode];
	if (rt == NULL)
		return 0;
	if (rt->rateCount > IEEE80211_RATE_MAXSIZE) {
		DPRINTF(sc, ATH_DEBUG_ANY,
			"%s: rate table too small (%u > %u)\n",
			__func__, rt->rateCount, IEEE80211_RATE_MAXSIZE);
		maxrates = IEEE80211_RATE_MAXSIZE;
	} else
		maxrates = rt->rateCount;
	rs = &ic->ic_sup_rates[mode];
	for (i = 0; i < maxrates; i++)
		rs->rs_rates[i] = rt->info[i].dot11Rate;
	rs->rs_nrates = maxrates;
	return 1;
}

static void
ath_setcurmode(struct ath_softc *sc, enum ieee80211_phymode mode)
{
#define	N(a)	(sizeof(a)/sizeof(a[0]))
	/* NB: on/off times from the Atheros NDIS driver, w/ permission */
	static const struct {
		u_int		rate;		/* tx/rx 802.11 rate */
		u_int16_t	timeOn;		/* LED on time (ms) */
		u_int16_t	timeOff;	/* LED off time (ms) */
	} blinkrates[] = {
		{ 108,  40,  10 },
		{  96,  44,  11 },
		{  72,  50,  13 },
		{  48,  57,  14 },
		{  36,  67,  16 },
		{  24,  80,  20 },
		{  22, 100,  25 },
		{  18, 133,  34 },
		{  12, 160,  40 },
		{  10, 200,  50 },
		{   6, 240,  58 },
		{   4, 267,  66 },
		{   2, 400, 100 },
		{   0, 500, 130 },
	};
	const HAL_RATE_TABLE *rt;
	int i, j;

	memset(sc->sc_rixmap, 0xff, sizeof(sc->sc_rixmap));
	rt = sc->sc_rates[mode];
	KASSERT(rt != NULL, ("no h/w rate set for phy mode %u", mode));
	for (i = 0; i < rt->rateCount; i++)
		sc->sc_rixmap[rt->info[i].dot11Rate & IEEE80211_RATE_VAL] = i;
	memset(sc->sc_hwmap, 0, sizeof(sc->sc_hwmap));
	for (i = 0; i < 32; i++) {
		u_int8_t ix = rt->rateCodeToIndex[i];
		if (ix == 0xff) {
			sc->sc_hwmap[i].ledon = (500 * HZ) / 1000;
			sc->sc_hwmap[i].ledoff = (130 * HZ) / 1000;
			continue;
		}
		sc->sc_hwmap[i].ieeerate =
			rt->info[ix].dot11Rate & IEEE80211_RATE_VAL;
		sc->sc_hwmap[i].txflags = IEEE80211_RADIOTAP_F_DATAPAD;
		if (rt->info[ix].shortPreamble ||
		    rt->info[ix].phy == IEEE80211_T_OFDM)
			sc->sc_hwmap[i].txflags |= IEEE80211_RADIOTAP_F_SHORTPRE;
		/* NB: receive frames include FCS */
		sc->sc_hwmap[i].rxflags = sc->sc_hwmap[i].txflags |
			IEEE80211_RADIOTAP_F_FCS;
		/* setup blink rate table to avoid per-packet lookup */
		for (j = 0; j < N(blinkrates)-1; j++)
			if (blinkrates[j].rate == sc->sc_hwmap[i].ieeerate)
				break;
		/* NB: this uses the last entry if the rate isn't found */
		/* XXX beware of overlow */
		sc->sc_hwmap[i].ledon = (blinkrates[j].timeOn * HZ) / 1000;
		sc->sc_hwmap[i].ledoff = (blinkrates[j].timeOff * HZ) / 1000;
	}
	sc->sc_currates = rt;
	sc->sc_curmode = mode;
	/*
	 * All protection frames are transmited at 2Mb/s for
	 * 11g, otherwise at 1Mb/s.
	 * XXX select protection rate index from rate table.
	 */
	sc->sc_protrix = ((mode == IEEE80211_MODE_11G || mode == IEEE80211_MODE_TURBO_G) ? 1 : 0);
	/* NB: caller is responsible for reseting rate control state */
#undef N
}


static int
ath_rawdev_attach(struct ath_softc *sc) 
{
	struct net_device *rawdev;
	unsigned t;
	rawdev = &sc->sc_rawdev;
	strcpy(rawdev->name, sc->sc_dev.name);
	strcat(rawdev->name, "raw");
	rawdev->priv = sc;

	/* ether_setup clobbers type, so save it */
	t = rawdev->type;
	ether_setup(rawdev);
	rawdev->type = t;

	rawdev->stop = NULL;
	rawdev->hard_start_xmit = ath_start_raw;
	rawdev->set_multicast_list = NULL;
	rawdev->get_stats = ath_getstats;
	rawdev->tx_queue_len = ATH_TXBUF;
	rawdev->flags |= IFF_NOARP;
	rawdev->flags &= ~IFF_MULTICAST;
	rawdev->mtu = IEEE80211_MAX_LEN;

	if (register_netdev(rawdev)) {
		goto bad;
	}

	if ((sc->sc_dev.flags & (IFF_RUNNING|IFF_UP)) == (IFF_RUNNING|IFF_UP))
		netif_start_queue(&sc->sc_rawdev);

	sc->sc_rawdev_enabled = 1;

	return 0;
 bad:
	return -1;
}

static void
ath_rawdev_detach(struct ath_softc *sc) 
{
	if (sc->sc_rawdev_enabled) {
		sc->sc_rawdev_enabled = 0;
		netif_stop_queue(&sc->sc_rawdev);
		unregister_netdev(&sc->sc_rawdev);
	}
}
#if IEEE80211_VLAN_TAG_USED
static void
ath_vlan_register(struct net_device *dev, struct vlan_group *grp)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_vlan_register(ic, grp);
}

static void
ath_vlan_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;

	ieee80211_vlan_kill_vid(ic, vid);
}
#endif /* IEEE80211_VLAN_TAG_USED */

#ifdef AR_DEBUG
static void
ath_printrxbuf(struct ath_buf *bf, int done)
{
	struct ath_desc *ds = bf->bf_desc;

	printk("R (%p %p) %08x %08x %08x %08x %08x %08x %c\n",
	    ds, (struct ath_desc *)bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1],
	    !done ? ' ' : (ds->ds_rxstat.rs_status == 0) ? '*' : '!');
}

static void
ath_printtxbuf(struct ath_buf *bf, int done)
{
	struct ath_desc *ds = bf->bf_desc;

	printk("T (%p %p) %08x %08x %08x %08x %08x %08x %08x %08x %c\n",
	    ds, (struct ath_desc *)bf->bf_daddr,
	    ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1,
	    ds->ds_hw[0], ds->ds_hw[1], ds->ds_hw[2], ds->ds_hw[3],
	    !done ? ' ' : (ds->ds_txstat.ts_status == 0) ? '*' : '!');
}
#endif /* AR_DEBUG */

/*
 * Return netdevice statistics.
 */
static struct net_device_stats *
ath_getstats(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct net_device_stats *stats = &sc->sc_devstats;

	/* update according to private statistics */
	stats->tx_errors = sc->sc_stats.ast_tx_encap
			 + sc->sc_stats.ast_tx_nonode
			 + sc->sc_stats.ast_tx_xretries
			 + sc->sc_stats.ast_tx_fifoerr
			 + sc->sc_stats.ast_tx_filtered
			 ;
	stats->tx_dropped = sc->sc_stats.ast_tx_nobuf
			+ sc->sc_stats.ast_tx_nobufmgt;
	stats->rx_errors = sc->sc_stats.ast_rx_tooshort
			+ sc->sc_stats.ast_rx_crcerr
			+ sc->sc_stats.ast_rx_fifoerr
			+ sc->sc_stats.ast_rx_badcrypt
			;
	stats->rx_crc_errors = sc->sc_stats.ast_rx_crcerr;

	return stats;
}

#ifdef CONFIG_NET_WIRELESS
/*
 * Return wireless extensions statistics.
 */
static struct iw_statistics *
ath_iw_getstats(struct net_device *dev)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct iw_statistics *is = &sc->sc_iwstats;

	ieee80211_iw_getstats(ic, is);
	/* add in statistics maintained by the driver */
	is->discard.code += sc->sc_stats.ast_rx_badcrypt;
	is->discard.retries += sc->sc_stats.ast_tx_xretries;
	is->discard.misc += sc->sc_stats.ast_tx_encap
			 + sc->sc_stats.ast_tx_nonode
			 + sc->sc_stats.ast_tx_xretries
			 + sc->sc_stats.ast_tx_fifoerr
			 + sc->sc_stats.ast_tx_filtered
			 + sc->sc_stats.ast_tx_nobuf
			 + sc->sc_stats.ast_tx_nobufmgt;
			 ;
	is->miss.beacon = sc->sc_stats.ast_bmiss;

	return &sc->sc_iwstats;
}

#include <net/iw_handler.h>
/*
 * Bounce functions to get to the 802.11 code. These are
 * necessary for now because wireless extensions operations
 * are done on the underlying device and not the 802.11 instance.
 * This will change when there can be multiple 802.11 instances
 * associated with a device and we must have a net_device for
 * each so we can manipulate them individually.
 */
#define	ATH_CHAR_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 char *erq, char *extra)				\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_POINT_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 struct iw_point *erq, char *extra)			\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_PARAM_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 struct iw_param *erq, char *extra)			\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_SOCKADDR_BOUNCE(name)					\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 struct sockaddr *erq, char *extra)			\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_FREQ_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 struct iw_freq *erq, char *extra)			\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_U32_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 __u32 *erq, char *extra)				\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}
#define	ATH_VOID_BOUNCE(name)						\
static int								\
ath_ioctl_##name(struct net_device *dev, struct iw_request_info *info,	\
	     	 void *erq, char *extra)				\
{									\
	struct ath_softc *sc = dev->priv;				\
	return ieee80211_ioctl_##name(&sc->sc_ic, info, erq, extra);	\
}

ATH_CHAR_BOUNCE(giwname)
ATH_POINT_BOUNCE(siwencode)
ATH_POINT_BOUNCE(giwencode)
ATH_PARAM_BOUNCE(siwrate)
ATH_PARAM_BOUNCE(giwrate)
ATH_PARAM_BOUNCE(siwsens)
ATH_PARAM_BOUNCE(giwsens)
ATH_PARAM_BOUNCE(siwrts)
ATH_PARAM_BOUNCE(giwrts)
ATH_PARAM_BOUNCE(siwfrag)
ATH_PARAM_BOUNCE(giwfrag)
ATH_SOCKADDR_BOUNCE(siwap)
ATH_SOCKADDR_BOUNCE(giwap)
ATH_POINT_BOUNCE(siwnickn)
ATH_POINT_BOUNCE(giwnickn)
ATH_FREQ_BOUNCE(siwfreq)
ATH_FREQ_BOUNCE(giwfreq)
ATH_POINT_BOUNCE(siwessid)
ATH_POINT_BOUNCE(giwessid)
ATH_POINT_BOUNCE(giwrange)
ATH_U32_BOUNCE(siwmode)
ATH_U32_BOUNCE(giwmode)
ATH_PARAM_BOUNCE(siwpower)
ATH_PARAM_BOUNCE(giwpower)
ATH_PARAM_BOUNCE(siwretry)
ATH_PARAM_BOUNCE(giwretry)
ATH_PARAM_BOUNCE(siwtxpow)
ATH_PARAM_BOUNCE(giwtxpow)
ATH_POINT_BOUNCE(iwaplist)
#ifdef SIOCGIWSCAN
ATH_POINT_BOUNCE(siwscan)
ATH_POINT_BOUNCE(giwscan)
#endif
ATH_VOID_BOUNCE(setparam)
ATH_VOID_BOUNCE(getparam)
ATH_VOID_BOUNCE(setkey)
ATH_VOID_BOUNCE(delkey)
ATH_VOID_BOUNCE(setmlme)
ATH_VOID_BOUNCE(setoptie)
ATH_VOID_BOUNCE(getoptie)
ATH_VOID_BOUNCE(addmac)
ATH_VOID_BOUNCE(delmac)
ATH_VOID_BOUNCE(chanlist)
#ifdef HAS_CU_SOFTMAC
static int ath_ioctl_getreg(struct net_device *dev,
                                     struct iw_request_info *info,
                                     void *wrqu, char *extra)
{
  struct ath_softc *sc = dev->priv;
  uint32_t reg = *((uint32_t *) extra);
  uint32_t *res = (uint32_t *) extra;

  //if (reg < 0x4000 || reg > 0x9000) {
  //  return -EINVAL;
  //}
  *res = OS_REG_READ(sc->sc_ah, reg);
  return 0;
}

static int ath_ioctl_setreg(struct net_device *dev,
			     struct iw_request_info *info,
			     void *wrqu, char *extra) 
{
  struct ath_softc *sc = dev->priv;
  int *i = (int *) extra;
  uint32_t reg = *i;
  uint32_t val = *(i + 1);
  
  //if (reg < 0x4000 || reg > 0x9000) {
  //  return -EINVAL;
  //}

  OS_REG_WRITE(sc->sc_ah, reg, val);
  return  0;
}
#endif

/* Structures to export the Wireless Handlers */
static const iw_handler ath_handlers[] = {
	(iw_handler) NULL,				/* SIOCSIWCOMMIT */
	(iw_handler) ath_ioctl_giwname,			/* SIOCGIWNAME */
	(iw_handler) NULL,				/* SIOCSIWNWID */
	(iw_handler) NULL,				/* SIOCGIWNWID */
	(iw_handler) ath_ioctl_siwfreq,			/* SIOCSIWFREQ */
	(iw_handler) ath_ioctl_giwfreq,			/* SIOCGIWFREQ */
	(iw_handler) ath_ioctl_siwmode,			/* SIOCSIWMODE */
	(iw_handler) ath_ioctl_giwmode,			/* SIOCGIWMODE */
	(iw_handler) ath_ioctl_siwsens,			/* SIOCSIWSENS */
	(iw_handler) ath_ioctl_giwsens,			/* SIOCGIWSENS */
	(iw_handler) NULL /* not used */,		/* SIOCSIWRANGE */
	(iw_handler) ath_ioctl_giwrange,		/* SIOCGIWRANGE */
	(iw_handler) NULL /* not used */,		/* SIOCSIWPRIV */
	(iw_handler) NULL /* kernel code */,		/* SIOCGIWPRIV */
	(iw_handler) NULL /* not used */,		/* SIOCSIWSTATS */
	(iw_handler) NULL /* kernel code */,		/* SIOCGIWSTATS */
	(iw_handler) NULL,				/* SIOCSIWSPY */
	(iw_handler) NULL,				/* SIOCGIWSPY */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) ath_ioctl_siwap,			/* SIOCSIWAP */
	(iw_handler) ath_ioctl_giwap,			/* SIOCGIWAP */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) ath_ioctl_iwaplist,		/* SIOCGIWAPLIST */
#ifdef SIOCGIWSCAN
	(iw_handler) ath_ioctl_siwscan,			/* SIOCSIWSCAN */
	(iw_handler) ath_ioctl_giwscan,			/* SIOCGIWSCAN */
#else
	(iw_handler) NULL,				/* SIOCSIWSCAN */
	(iw_handler) NULL,				/* SIOCGIWSCAN */
#endif /* SIOCGIWSCAN */
	(iw_handler) ath_ioctl_siwessid,		/* SIOCSIWESSID */
	(iw_handler) ath_ioctl_giwessid,		/* SIOCGIWESSID */
	(iw_handler) ath_ioctl_siwnickn,		/* SIOCSIWNICKN */
	(iw_handler) ath_ioctl_giwnickn,		/* SIOCGIWNICKN */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) NULL,				/* -- hole -- */
	(iw_handler) ath_ioctl_siwrate,			/* SIOCSIWRATE */
	(iw_handler) ath_ioctl_giwrate,			/* SIOCGIWRATE */
	(iw_handler) ath_ioctl_siwrts,			/* SIOCSIWRTS */
	(iw_handler) ath_ioctl_giwrts,			/* SIOCGIWRTS */
	(iw_handler) ath_ioctl_siwfrag,			/* SIOCSIWFRAG */
	(iw_handler) ath_ioctl_giwfrag,			/* SIOCGIWFRAG */
	(iw_handler) ath_ioctl_siwtxpow,		/* SIOCSIWTXPOW */
	(iw_handler) ath_ioctl_giwtxpow,		/* SIOCGIWTXPOW */
	(iw_handler) ath_ioctl_siwretry,		/* SIOCSIWRETRY */
	(iw_handler) ath_ioctl_giwretry,		/* SIOCGIWRETRY */
	(iw_handler) ath_ioctl_siwencode,		/* SIOCSIWENCODE */
	(iw_handler) ath_ioctl_giwencode,		/* SIOCGIWENCODE */
	(iw_handler) ath_ioctl_siwpower,		/* SIOCSIWPOWER */
	(iw_handler) ath_ioctl_giwpower,		/* SIOCGIWPOWER */
};
static const iw_handler ath_priv_handlers[] = {
	(iw_handler) ath_ioctl_setparam,		/* SIOCWFIRSTPRIV+0 */
	(iw_handler) ath_ioctl_getparam,		/* SIOCWFIRSTPRIV+1 */
	(iw_handler) ath_ioctl_setkey,			/* SIOCWFIRSTPRIV+2 */
	(iw_handler) NULL,				/* SIOCWFIRSTPRIV+3 */
	(iw_handler) ath_ioctl_delkey,			/* SIOCWFIRSTPRIV+4 */
	(iw_handler) NULL,				/* SIOCWFIRSTPRIV+5 */
	(iw_handler) ath_ioctl_setmlme,			/* SIOCWFIRSTPRIV+6 */
	(iw_handler) NULL,				/* SIOCWFIRSTPRIV+7 */
	(iw_handler) ath_ioctl_setoptie,		/* SIOCWFIRSTPRIV+8 */
	(iw_handler) ath_ioctl_getoptie,		/* SIOCWFIRSTPRIV+9 */
	(iw_handler) ath_ioctl_addmac,			/* SIOCWFIRSTPRIV+10 */
	(iw_handler) NULL,				/* SIOCWFIRSTPRIV+11 */
	(iw_handler) ath_ioctl_delmac,			/* SIOCWFIRSTPRIV+12 */
	(iw_handler) NULL,				/* SIOCWFIRSTPRIV+13 */
	(iw_handler) ath_ioctl_chanlist,		/* SIOCWFIRSTPRIV+14 */
#ifdef HAS_CU_SOFTMAC
	(iw_handler) NULL,
	(iw_handler) ath_ioctl_setreg, 
	(iw_handler) ath_ioctl_getreg, 
#endif
};

static struct iw_handler_def ath_iw_handler_def = {
#define	N(a)	(sizeof (a) / sizeof (a[0]))
	.standard		= (iw_handler *) ath_handlers,
	.num_standard		= N(ath_handlers),
	.private		= (iw_handler *) ath_priv_handlers,
	.num_private		= N(ath_priv_handlers),
#undef N
};
#endif /* CONFIG_NET_WIRELESS */

static int
ath_set_mac_address(struct net_device *dev, void *addr)
{
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	struct sockaddr *mac = addr;
	int error;

	if (netif_running(dev)) {
		DPRINTF(sc, ATH_DEBUG_ANY,
			"%s: cannot set address; device running\n", __func__);
		return -EBUSY;
	}
	DPRINTF(sc, ATH_DEBUG_ANY, "%s: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		__func__,
		mac->sa_data[0], mac->sa_data[1], mac->sa_data[2],
		mac->sa_data[3], mac->sa_data[4], mac->sa_data[5]);

	ATH_LOCK(sc);
	/* XXX not right for multiple vap's */
	IEEE80211_ADDR_COPY(ic->ic_myaddr, mac->sa_data);
	IEEE80211_ADDR_COPY(dev->dev_addr, mac->sa_data);
	ath_hal_setmac(ah, dev->dev_addr);
	error = -ath_reset(dev);
	ATH_UNLOCK(sc);

	return error;
}

static int      
ath_change_mtu(struct net_device *dev, int mtu) 
{
	struct ath_softc *sc = dev->priv;
	int error;

	if (!(ATH_MIN_MTU < mtu && mtu <= ATH_MAX_MTU)) {
		DPRINTF(sc, ATH_DEBUG_ANY, "%s: invalid %d, min %u, max %u\n",
			__func__, mtu, ATH_MIN_MTU, ATH_MAX_MTU);
		return -EINVAL;
	}
	DPRINTF(sc, ATH_DEBUG_ANY, "%s: %d\n", __func__, mtu);

	ATH_LOCK(sc);
	dev->mtu = mtu;
	/* NB: the rx buffers may need to be reallocated */
	tasklet_disable(&sc->sc_rxtq);
	error = -ath_reset(dev);
	tasklet_enable(&sc->sc_rxtq);
	ATH_UNLOCK(sc);

	return error;
}

/*
 * Diagnostic interface to the HAL.  This is used by various
 * tools to do things like retrieve register contents for
 * debugging.  The mechanism is intentionally opaque so that
 * it can change frequently w/o concern for compatiblity.
 */
static int
ath_ioctl_diag(struct ath_softc *sc, struct ath_diag *ad)
{
	struct ath_hal *ah = sc->sc_ah;
	u_int id = ad->ad_id & ATH_DIAG_ID;
	void *indata = NULL;
	void *outdata = NULL;
	u_int32_t insize = ad->ad_in_size;
	u_int32_t outsize = ad->ad_out_size;
	int error = 0;

	if (ad->ad_id & ATH_DIAG_IN) {
		/*
		 * Copy in data.
		 */
		indata = kmalloc(insize, GFP_KERNEL);
		if (indata == NULL) {
			error = -ENOMEM;
			goto bad;
		}
		if (copy_from_user(indata, ad->ad_in_data, insize)) {
			error = -EFAULT;
			goto bad;
		}
	}
	if (ad->ad_id & ATH_DIAG_DYN) {
		/*
		 * Allocate a buffer for the results (otherwise the HAL
		 * returns a pointer to a buffer where we can read the
		 * results).  Note that we depend on the HAL leaving this
		 * pointer for us to use below in reclaiming the buffer;
		 * may want to be more defensive.
		 */
		outdata = kmalloc(outsize, GFP_KERNEL);
		if (outdata == NULL) {
			error = -ENOMEM;
			goto bad;
		}
	}
	if (ath_hal_getdiagstate(ah, id, indata, insize, &outdata, &outsize)) {
		if (outsize < ad->ad_out_size)
			ad->ad_out_size = outsize;
		if (outdata &&
		     copy_to_user(ad->ad_out_data, outdata, ad->ad_out_size))
			error = -EFAULT;
	} else {
		error = -EINVAL;
	}
bad:
	if ((ad->ad_id & ATH_DIAG_IN) && indata != NULL)
		kfree(indata);
	if ((ad->ad_id & ATH_DIAG_DYN) && outdata != NULL)
		kfree(outdata);
	return error;
}

extern	int ath_ioctl_ethtool(struct ath_softc *sc, int cmd, void *addr);

static int
ath_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
#define	IS_RUNNING(dev) \
	((dev->flags & (IFF_RUNNING|IFF_UP)) == (IFF_RUNNING|IFF_UP))
	struct ath_softc *sc = dev->priv;
	struct ieee80211com *ic = &sc->sc_ic;
	int error = 0;

	ATH_LOCK(sc);
	switch (cmd) {
	case SIOCSIFFLAGS:
		if (IS_RUNNING(dev)) {
			/*
			 * To avoid rescanning another access point,
			 * do not call ath_init() here.  Instead,
			 * only reflect promisc mode settings.
			 */
			ath_mode_init(dev);
		} else if (dev->flags & IFF_UP) {
			/*
			 * Beware of being called during attach/detach
			 * to reset promiscuous mode.  In that case we
			 * will still be marked UP but not RUNNING.
			 * However trying to re-init the interface
			 * is the wrong thing to do as we've already
			 * torn down much of our state.  There's
			 * probably a better way to deal with this.
			 */
			if (!sc->sc_invalid && ic->ic_bss != NULL)
				ath_init(dev);	/* XXX lose error */
		} else
			ath_stop_locked(dev);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		/*
		 * The upper layer has already installed/removed
		 * the multicast address(es), just recalculate the
		 * multicast filter for the card.
		 */
		if (dev->flags & IFF_RUNNING)
			ath_mode_init(dev);
		break;
	case SIOCGATHSTATS:
		/* NB: embed these numbers to get a consistent view */
		sc->sc_stats.ast_tx_packets = ic->ic_devstats->tx_packets;
		sc->sc_stats.ast_rx_packets = ic->ic_devstats->rx_packets;
		sc->sc_stats.ast_rx_rssi = ieee80211_getrssi(ic);
		ATH_UNLOCK(sc);
		if (copy_to_user(ifr->ifr_data, &sc->sc_stats,
		    sizeof (sc->sc_stats)))
			error = -EFAULT;
		else
			error = 0;
		break;
	case SIOCGATHDIAG:
		if (!capable(CAP_NET_ADMIN))
			error = -EPERM;
		else
			error = ath_ioctl_diag(sc, (struct ath_diag *) ifr);
		break;
	case SIOCETHTOOL:
		if (copy_from_user(&cmd, ifr->ifr_data, sizeof(cmd)))
			error = -EFAULT;
		else
			error = ath_ioctl_ethtool(sc, cmd, ifr->ifr_data);
			break;
	default:
		error = ieee80211_ioctl(ic, ifr, cmd);
		if (error == -ENETRESET) {
			if (IS_RUNNING(dev) && 
			    ic->ic_roaming != IEEE80211_ROAMING_MANUAL)
				ath_init(dev);	/* XXX lose error */
			error = 0;
		}
		if (error == -ERESTART)
			error = IS_RUNNING(dev) ? ath_reset(dev) : 0;
		break;
	}
	ATH_UNLOCK(sc);
	return error;
#undef IS_RUNNING
}

#ifdef CONFIG_SYSCTL
/*
 * Sysctls are split into ``static'' and ``dynamic'' tables.
 * The former are defined at module load time and are used
 * control parameters common to all devices.  The latter are
 * tied to particular device instances and come and go with
 * each device.  The split is currently a bit tenuous; many of
 * the static ones probably should be dynamic but having them
 * static (e.g. debug) means they can be set after a module is
 * loaded and before bringing up a device.  The alternative
 * is to add module parameters.
 */

/*
 * Dynamic (i.e. per-device) sysctls.  These are automatically
 * mirrored in /proc/sys.
 */
enum {
	ATH_SLOTTIME	= 1,
	ATH_ACKTIMEOUT	= 2,
	ATH_CTSTIMEOUT	= 3,
	ATH_SOFTLED	= 4,
	ATH_LEDPIN	= 5,
	ATH_COUNTRYCODE	= 6,
	ATH_REGDOMAIN	= 7,
	ATH_DEBUG	= 8,
	ATH_TXANTENNA	= 9,
	ATH_RXANTENNA	= 10,
	ATH_DIVERSITY	= 11,
	ATH_TXINTRPERIOD= 12,
	ATH_TPSCALE     = 13,
	ATH_TPC         = 14,
	ATH_TXPOWLIMIT  = 15,	
	ATH_VEOL        = 16,
	ATH_BINTVAL	= 17,
	ATH_RAWDEV      = 18,
	ATH_RAWDEV_TYPE = 19,
	ATH_RXFILTER   = 20,
	ATH_RADARSIM   = 21,
};

#ifdef HAS_CU_SOFTMAC
enum {
	ATH_CU_SOFTMAC = 1,
	ATH_CU_SOFTMAC_RAW80211 = 2,
	ATH_CU_SOFTMAC_PHOCUS_SETTLETIME = 3,
	ATH_CU_SOFTMAC_PHOCUS_ENABLE = 4,
	ATH_CU_SOFTMAC_PHOCUS_STATE = 5,
	ATH_CU_SOFTMAC_WIFIVERSION = 6,
	ATH_CU_SOFTMAC_WIFITYPE = 7,
	ATH_CU_SOFTMAC_WIFISUBTYPE = 8,
	ATH_CU_SOFTMAC_WIFIFLAGS = 9,
	ATH_CU_SOFTMAC_NOAUTOCALIBRATE = 10,
	ATH_CU_SOFTMAC_CALIBRATE_NOW = 11,
	ATH_CU_SOFTMAC_PHY_NF_RAW = 12,
	ATH_CU_SOFTMAC_MAC = 13
};

enum {
  ATH_CU_SOFTMAC_TX_ON_TXINTR_NO = 0,
  ATH_CU_SOFTMAC_TX_ON_TXINTR_DEFER = 1,
  ATH_CU_SOFTMAC_TX_ON_TXINTR_IMMEDIATE = 2,
};

struct ath_cu_softmac_proc_data {
    struct list_head list;
    struct ath_softc* sc;
    int id;
    char name[CU_SOFTMAC_NAME_SIZE];
    struct proc_dir_entry* parent;  
};

struct ath_cu_softmac_proc_entry {
    const char *procname;
    mode_t mode;
    int ctl_name;
};

static const struct ath_cu_softmac_proc_entry athphy_proc_entries[] = {
    { .ctl_name	= ATH_CU_SOFTMAC,
      .procname	= "softmac_enable",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_RAW80211,
      .procname	= "raw_mode",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_PHOCUS_SETTLETIME,
      .procname	= "phocus_settletime",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_PHY_NF_RAW,
      .procname	= "nf_raw",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_PHOCUS_ENABLE,
      .procname	= "phocus_enable",
      .mode     = 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_PHOCUS_STATE,
      .procname	= "phocus_state",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_WIFIVERSION,
      .procname	= "wifiversion",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_WIFITYPE,
      .procname	= "wifitype",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_WIFISUBTYPE,
      .procname	= "wifisubtype",
      .mode     = 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_WIFIFLAGS,
      .procname	= "wififlags",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_NOAUTOCALIBRATE,
      .procname	= "noautocalibrate",
      .mode	= 0644,
    },
    { .ctl_name	= ATH_CU_SOFTMAC_CALIBRATE_NOW,
      .procname	= "calibrate_now",
      .mode	= 0200,
    },
    { .ctl_name = ATH_CU_SOFTMAC_MAC,
      .procname = "mac_layer",
      .mode     = 0644,
    },
    /* terminator, don't remove */
    { .ctl_name = 0,
      .procname = 0,
      .mode = 0,
    },
};

static int
ath_cu_softmac_athphy_make_procfs(struct ath_softc *sc)
{
    int i, result = 0;
    struct proc_dir_entry *ent, *root;
    struct ath_cu_softmac_proc_data *proc_data;

    if (sc) {
	root = sc->sc_cu_softmac_phy->proc;
	
	for (i=0; (athphy_proc_entries[i].procname && athphy_proc_entries[i].procname[0]); i++) {
	    ent = create_proc_entry(athphy_proc_entries[i].procname,
				    athphy_proc_entries[i].mode,
				    root);
	    ent->owner = THIS_MODULE;
	    ent->read_proc = ath_cu_softmac_athphy_read_proc;
	    ent->write_proc = ath_cu_softmac_athphy_write_proc;
	    ent->data = kmalloc(sizeof(struct ath_cu_softmac_proc_data), GFP_ATOMIC);

	    proc_data = ent->data;
	    INIT_LIST_HEAD(&(proc_data->list));
	    list_add_tail(&(proc_data->list), &(sc->sc_cu_softmac_procfs_data));
	    proc_data->sc = sc;
	    proc_data->id = athphy_proc_entries[i].ctl_name;
	    strncpy(proc_data->name, athphy_proc_entries[i].procname, CU_SOFTMAC_NAME_SIZE);
	    proc_data->parent = root;
	}
    }
    return result;
}

static int
ath_cu_softmac_athphy_delete_procfs(struct ath_softc *sc)
{
    int result = 0;
    if (sc) {
	struct list_head* tmp = 0;
	struct list_head* p = 0;
	struct ath_cu_softmac_proc_data* proc_entry_data = 0;

	/*
	 * Remove individual entries and delete their data
	 */
	list_for_each_safe(p, tmp, &(sc->sc_cu_softmac_procfs_data)) {
	    proc_entry_data = list_entry(p, struct ath_cu_softmac_proc_data, list);
	    list_del(p);
	    remove_proc_entry(proc_entry_data->name, proc_entry_data->parent);
	    kfree(proc_entry_data);
	    proc_entry_data = 0;
	}
	
    }
    return result;
}

static int
ath_cu_softmac_athphy_read_proc(char *page, char **start, off_t off, 
				int count, int *eof, void *data) 
{
    int result = 0;
    struct ath_cu_softmac_proc_data* procdata = data;
    if (procdata && procdata->sc) {
	struct ath_softc *sc = procdata->sc;
	char* dest = (page + off);
	int intval = 0;
	
	switch (procdata->id) {
	case ATH_CU_SOFTMAC:
	    intval = sc->sc_cu_softmac;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;
	    break;
	case ATH_CU_SOFTMAC_RAW80211:
	    // Allow softmac to operate on the whole 802.11 frame
	    if ((sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_RAW_MODE)) {
		intval = 1;
	    }
	    else {
		intval = 0;
	    }
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_SETTLETIME:
	    // allow phocus time to settle after steering
	    intval =sc->sc_cu_softmac_phocus_settletime;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;    	    
	case ATH_CU_SOFTMAC_PHY_NF_RAW:
	    // get value for the PHY_NF register
	    intval =OS_REG_READ(sc->sc_ah,39012);
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_ENABLE:
	    // enable use of phocus antenna
	    intval =sc->sc_cu_softmac_phocus_enable;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_STATE:
	    // configuration of phocus antenna
	    intval =sc->sc_cu_softmac_phocus_state;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_WIFIVERSION:
	    // get the wifi version encap field
	    intval =sc->sc_cu_softmac_wifictl0 & 0x3;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_WIFITYPE:
	    // get the wifi type encap field
	    intval =(sc->sc_cu_softmac_wifictl0 >> 2) & 0x3;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_WIFISUBTYPE:
	    // get the wifi subtype encap field
	    intval =(sc->sc_cu_softmac_wifictl0 >> 4) & 0xF;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_WIFIFLAGS:
	    // get the wifi flags encap field
	    intval =sc->sc_cu_softmac_wifictl1;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	    break;
	case ATH_CU_SOFTMAC_NOAUTOCALIBRATE:
	    intval =sc->sc_cu_softmac_noautocalibrate;
	    break;
	    result = snprintf(dest,count, "%d\n", intval);
	    *eof = 1;	
	case ATH_CU_SOFTMAC_MAC:
	    if (sc->sc_cu_softmac_mac == sc->sc_cu_softmac_defaultmac)
		result = snprintf(dest, count, "0\n");
	    else
		result = snprintf(dest, count, "%s\n", sc->sc_cu_softmac_mac->name);
	    *eof = 1;	
	    break;
	default:
	    result = 0;
	    *eof = 1;
	    break;
	}
    }
    return result;
}

static int
ath_cu_softmac_athphy_write_proc(struct file *file, const char __user *buffer, 
				 unsigned long count, void *data)
{
    int result = 0;
    struct ath_cu_softmac_proc_data* procdata = data;
    CU_SOFTMAC_MACLAYER_INFO *mac;

    if (procdata && procdata->sc) {
	struct ath_softc *sc = procdata->sc;
	struct ath_hal *ah = sc->sc_ah;
	static const int maxkdatalen = 256;
	char kdata[maxkdatalen];
	char* endp = 0;
	long val = 0;
	
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
	
	switch (procdata->id) {
	case ATH_CU_SOFTMAC:
	    // allow "softmac" access when in monitor mode
	    val = simple_strtol(kdata, &endp, 10);
	    sc->sc_cu_softmac = val;
	    if (val) {
		// Make sure we receive ALL the packets from the hal...
		ath_hal_setrxfilter(ah,ATH_CU_SOFTMAC_HAL_RX_FILTER_ALLOWALL);
	    }
	    break;
	case ATH_CU_SOFTMAC_RAW80211:
	    // Allow softmac to operate on the
	    // whole 802.11 frame.
	    val = simple_strtol(kdata, &endp, 10);
	    if (val) {
		sc->sc_cu_softmac_options |= CU_SOFTMAC_ATH_RAW_MODE;
	    }
	    else {
		sc->sc_cu_softmac_options &= ~CU_SOFTMAC_ATH_RAW_MODE;
	    }
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_SETTLETIME:
	    // delay to use for phocus antenna
	    val = simple_strtol(kdata, &endp, 10);
	    sc->sc_cu_softmac_phocus_settletime = val;
	    break;
	case ATH_CU_SOFTMAC_PHY_NF_RAW:
	    // set a value for the PHY_NF register
	    val = simple_strtol(kdata, &endp, 10);
	    OS_REG_WRITE(sc->sc_ah,39012,val);
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_ENABLE:
	    // enable the phocus antenna unit
	    val = simple_strtol(kdata, &endp, 10);
	    sc->sc_cu_softmac_phocus_enable = val;
	    break;
	case ATH_CU_SOFTMAC_PHOCUS_STATE:
	    // configure the phocus antenna unit
	    val = simple_strtol(kdata, &endp, 10);
	    if (sc->sc_cu_softmac_phocus_enable && 
		(val != sc->sc_cu_softmac_phocus_state)) {
		sc->sc_cu_softmac_phocus_state = val;
		cu_softmac_ath_set_phocus_state(sc->sc_cu_softmac_phocus_state, 
						sc->sc_cu_softmac_phocus_settletime);
	    }
	    break;
	case ATH_CU_SOFTMAC_WIFIVERSION:
	    {
		u_int8_t wctl0 = sc->sc_cu_softmac_wifictl0;
		// set the wifi version encap field
		val = simple_strtol(kdata, &endp, 10);
		wctl0 &= ~(0x3); 
		wctl0 |= (val & 0x3);
		sc->sc_cu_softmac_wifictl0 = wctl0;
	    }
	    break;
	case ATH_CU_SOFTMAC_WIFITYPE:
	    {
		u_int8_t wctl0 = sc->sc_cu_softmac_wifictl0;
		// set the wifi type encap field
		val = simple_strtol(kdata, &endp, 10);
		wctl0 &= ~(0x3 << 2);
		wctl0 |= ((val & 0x3) << 2);
		sc->sc_cu_softmac_wifictl0 = wctl0;
	    }
	    break;
	case ATH_CU_SOFTMAC_WIFISUBTYPE:
	    {
		u_int8_t wctl0 = sc->sc_cu_softmac_wifictl0;
		val = simple_strtol(kdata, &endp, 10);
		// set the wifi subtype encap field
		wctl0 &= ~(0xF << 4);
		wctl0 |= ((val & 0xF) << 4);
		sc->sc_cu_softmac_wifictl0 = wctl0;
	    }
	    break;
	case ATH_CU_SOFTMAC_WIFIFLAGS:
	    {
		val = simple_strtol(kdata, &endp, 10);
		sc->sc_cu_softmac_wifictl1 = (val & 0xFF);
	    }
	    break;
	case ATH_CU_SOFTMAC_NOAUTOCALIBRATE:
	    val = simple_strtol(kdata, &endp, 10);
	    sc->sc_cu_softmac_noautocalibrate = val;
	    break;
	case ATH_CU_SOFTMAC_CALIBRATE_NOW:
	    ath_calibrate_now(&(sc->sc_dev));
	    break;
	case ATH_CU_SOFTMAC_MAC:
	    if (result > CU_SOFTMAC_NAME_SIZE)
		result = CU_SOFTMAC_NAME_SIZE;
	    kdata[result-1] = 0;

	    /* detach any mac already attached */
	    sc->sc_cu_softmac_mac->cu_softmac_mac_detach(sc->sc_cu_softmac_mac->mac_private);
	    cu_softmac_phy_detach_ath(sc);

	    /* try to attach a new mac */
	    mac = cu_softmac_macinfo_get_by_name(kdata);
	    if (mac) {
		cu_softmac_phy_attach_ath(sc, mac);
		mac->cu_softmac_mac_attach(mac->mac_private, sc->sc_cu_softmac_phy);
		cu_softmac_macinfo_free(mac);
		printk("%s: attached to %s\n", sc->sc_cu_softmac_phy->name, kdata);
	    }

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
#endif

static int
ATH_SYSCTL_DECL(ath_sysctl_halparam, ctl, write, filp, buffer, lenp, ppos)
{
	struct ath_softc *sc = ctl->extra1;
	struct ath_hal *ah = sc->sc_ah;
	u_int val;
	int ret;

	ctl->data = &val;
	ctl->maxlen = sizeof(val);
	if (write) {
		ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
				lenp, ppos);
		if (ret == 0) {
			switch (ctl->ctl_name) {
			case ATH_SLOTTIME:
				if (!ath_hal_setslottime(ah, val))
					ret = -EINVAL;
				break;
			case ATH_ACKTIMEOUT:
				if (!ath_hal_setacktimeout(ah, val))
					ret = -EINVAL;
				break;
			case ATH_CTSTIMEOUT:
				if (!ath_hal_setctstimeout(ah, val))
					ret = -EINVAL;
				break;
			case ATH_SOFTLED:
				if (val != sc->sc_softled) {
					if (val)
						ath_hal_gpioCfgOutput(ah,
							sc->sc_ledpin);
					ath_hal_gpioset(ah, sc->sc_ledpin,!val);
					sc->sc_softled = val;
				}
				break;
			case ATH_LEDPIN:
				sc->sc_ledpin = val;
				break;
			case ATH_DEBUG:
				sc->sc_debug = val;
				break;
			case ATH_TXANTENNA:
				/* XXX validate? */
				sc->sc_txantenna = val;
				break;
			case ATH_RXANTENNA:
				/* XXX validate? */
				ath_setdefantenna(sc, val);
				break;
			case ATH_DIVERSITY:
				/* XXX validate? */
				if (!sc->sc_hasdiversity)
					return -EINVAL;
				sc->sc_diversity = val;
				ath_hal_setdiversity(ah, val);
				break;
			case ATH_TXINTRPERIOD:
				sc->sc_txintrperiod = val;
				break;
                        case ATH_TPSCALE:
                                /* XXX validate? */
				// TODO: error handling
                                ath_hal_settpscale(ah, val);
                                break;
                        case ATH_TPC:
                                /* XXX validate? */
                                if (!sc->sc_hastpc)
                                        return -EINVAL;
                                ath_hal_settpc(ah, val);
                                break;
                        case ATH_TXPOWLIMIT:
                                /* XXX validate? */
                                ath_hal_settxpowlimit(ah, val);
                                break;
                        case ATH_BINTVAL:
				if ((sc->sc_ic).ic_opmode != IEEE80211_M_HOSTAP &&
    					(sc->sc_ic).ic_opmode != IEEE80211_M_IBSS)
                    		    return -EINVAL;
            			if (IEEE80211_BINTVAL_MIN <= val &&
                			val <= IEEE80211_BINTVAL_MAX) {
                    		    (sc->sc_ic).ic_lintval = val;
                    		ret = -ENETRESET;              /* requires restart */
            			} else
                    		    ret = -EINVAL;
                                break;
			case ATH_RAWDEV:
				if (val && !sc->sc_rawdev_enabled) {
					ath_rawdev_attach(sc);
				} else if (!val && sc->sc_rawdev_enabled) {
					ath_rawdev_detach(sc);
				}
				ath_reset(&sc->sc_dev);
				break;
			case ATH_RAWDEV_TYPE:
				switch (val) {
				case 0: 
					sc->sc_rawdev.type = ARPHRD_IEEE80211;
					break;
				case 1: 
					sc->sc_rawdev.type = ARPHRD_IEEE80211_PRISM;
					break;
				case 2: 
					sc->sc_rawdev.type = ARPHRD_IEEE80211_RADIOTAP;
					break;
				default:
					return -EINVAL;
				}
				ath_reset(&sc->sc_dev);
				break;
			case ATH_RXFILTER:
				sc->sc_rxfilter = val;
#ifdef HAS_CU_SOFTMAC
				ath_reset(&sc->sc_dev);
#else
				ath_hal_setrxfilter(ah,HAL_RX_FILTER_ALLOWALL);
#endif
				break;
			case ATH_RADARSIM:
				ATH_SCHEDULE_TQUEUE (&sc->sc_radartq, &needmark);
				break;
			default:
				return -EINVAL;
			}
		}
	} else {
		switch (ctl->ctl_name) {
		case ATH_SLOTTIME:
			val = ath_hal_getslottime(ah);
			break;
		case ATH_ACKTIMEOUT:
			val = ath_hal_getacktimeout(ah);
			break;
		case ATH_CTSTIMEOUT:
			val = ath_hal_getctstimeout(ah);
			break;
		case ATH_SOFTLED:
			val = sc->sc_softled;
			break;
		case ATH_LEDPIN:
			val = sc->sc_ledpin;
			break;
		case ATH_COUNTRYCODE:
			ath_hal_getcountrycode(ah, &val);
			break;
		case ATH_REGDOMAIN:
			ath_hal_getregdomain(ah, &val);
			break;
		case ATH_DEBUG:
			val = sc->sc_debug;
			break;
		case ATH_TXANTENNA:
			val = sc->sc_txantenna;
			break;
		case ATH_RXANTENNA:
			val = ath_hal_getdefantenna(ah);
			break;
		case ATH_DIVERSITY:
			val = sc->sc_diversity;
			break;
		case ATH_TXINTRPERIOD:
			val = sc->sc_txintrperiod;
			break;
		case ATH_TPSCALE:
			ath_hal_gettpscale(ah, &val);
			break;
		case ATH_TPC:
			val = ath_hal_gettpc(ah);
			break;
		case ATH_TXPOWLIMIT:
			ath_hal_gettxpowlimit(ah, &val);
			break;
		case ATH_VEOL:
			val = sc->sc_hasveol;
 			break;
		case ATH_BINTVAL:
			val = (sc->sc_ic).ic_lintval;
 			break;
		case ATH_RAWDEV:
			val = sc->sc_rawdev_enabled;
 			break;
		case ATH_RAWDEV_TYPE:
			switch (sc->sc_rawdev.type) {
			case ARPHRD_IEEE80211:          val = 0; break;
			case ARPHRD_IEEE80211_PRISM:    val = 1; break;
			case ARPHRD_IEEE80211_RADIOTAP: val = 2; break;
			default: 
				val = 0;
			}
 			break;
		case ATH_RXFILTER:
#ifdef HAS_CU_SOFTMAC
		  val = ath_hal_getrxfilter(ah);
#else
			val = sc->sc_rxfilter;
#endif
			break;
		case ATH_RADARSIM:
			val = 0;
			break;
		default:
			return -EINVAL;
		}
		ret = ATH_SYSCTL_PROC_DOINTVEC(ctl, write, filp, buffer,
				lenp, ppos);
	}
	return ret;
}

static	int mindwelltime = 100;			/* 100ms */
static	int mincalibrate = 1;			/* once a second */
static	int maxint = 0x7fffffff;		/* 32-bit big */

#define	CTL_AUTO	-2	/* cannot be CTL_ANY or CTL_NONE */

static const ctl_table ath_sysctl_template[] = {
	{ .ctl_name	= ATH_SLOTTIME,
	  .procname	= "slottime",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_ACKTIMEOUT,
	  .procname	= "acktimeout",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_CTSTIMEOUT,
	  .procname	= "ctstimeout",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_SOFTLED,
	  .procname	= "softled",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_LEDPIN,
	  .procname	= "ledpin",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_COUNTRYCODE,
	  .procname	= "countrycode",
	  .mode		= 0444,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_REGDOMAIN,
	  .procname	= "regdomain",
	  .mode		= 0444,
	  .proc_handler	= ath_sysctl_halparam
	},
#ifdef AR_DEBUG
	{ .ctl_name	= ATH_DEBUG,
	  .procname	= "debug",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
#endif
	{ .ctl_name	= ATH_TXANTENNA,
	  .procname	= "txantenna",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_RXANTENNA,
	  .procname	= "rxantenna",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_DIVERSITY,
	  .procname	= "diversity",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_TXINTRPERIOD,
	  .procname	= "txintrperiod",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_TPSCALE,
	  .procname	= "tpscale",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_TPC,
	  .procname	= "tpc",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_TXPOWLIMIT,
	  .procname	= "txpowlimit",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_VEOL,
	  .procname	= "veol",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_BINTVAL,
	  .procname	= "bintval",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_RAWDEV,
	  .procname	= "rawdev",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_RAWDEV_TYPE,
	  .procname	= "rawdev_type",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_RXFILTER,
	  .procname	= "rxfilter",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ .ctl_name	= ATH_RADARSIM,
	  .procname	= "radarsim",
	  .mode		= 0644,
	  .proc_handler	= ath_sysctl_halparam
	},
	{ 0 }
};

static void
ath_dynamic_sysctl_register(struct ath_softc *sc)
{
	int i, space;

	space = 5*sizeof(struct ctl_table) + sizeof(ath_sysctl_template);
	sc->sc_sysctls = kmalloc(space, GFP_KERNEL);
	if (sc->sc_sysctls == NULL) {
		printk("%s: no memory for sysctl table!\n", __func__);
		return;
	}

	/* setup the table */
	memset(sc->sc_sysctls, 0, space);
	sc->sc_sysctls[0].ctl_name = CTL_DEV;
	sc->sc_sysctls[0].procname = "dev";
	sc->sc_sysctls[0].mode = 0555;
	sc->sc_sysctls[0].child = &sc->sc_sysctls[2];
	/* [1] is NULL terminator */
	sc->sc_sysctls[2].ctl_name = CTL_AUTO;
	sc->sc_sysctls[2].procname = sc->sc_dev.name;
	sc->sc_sysctls[2].mode = 0555;
	sc->sc_sysctls[2].child = &sc->sc_sysctls[4];
	/* [3] is NULL terminator */
	/* copy in pre-defined data */
	memcpy(&sc->sc_sysctls[4], ath_sysctl_template,
		sizeof(ath_sysctl_template));

	/* add in dynamic data references */
	for (i = 4; sc->sc_sysctls[i].ctl_name; i++)
		if (sc->sc_sysctls[i].extra1 == NULL)
			sc->sc_sysctls[i].extra1 = sc;

	/* and register everything */
	sc->sc_sysctl_header = register_sysctl_table(sc->sc_sysctls, 1);
	if (!sc->sc_sysctl_header) {
		printk("%s: failed to register sysctls!\n", sc->sc_dev.name);
		kfree(sc->sc_sysctls);
		sc->sc_sysctls = NULL;
	}

	/* initialize values */
#ifdef AR_DEBUG
	sc->sc_debug = ath_debug;
#endif
	sc->sc_txantenna = 0;		/* default to auto-selection */
	sc->sc_txintrperiod = ATH_TXINTR_PERIOD;
}

static void
ath_dynamic_sysctl_unregister(struct ath_softc *sc)
{
	if (sc->sc_sysctl_header) {
		unregister_sysctl_table(sc->sc_sysctl_header);
		sc->sc_sysctl_header = NULL;
	}
	if (sc->sc_sysctls) {
		kfree(sc->sc_sysctls);
		sc->sc_sysctls = NULL;
	}
}

/*
 * Announce various information on device/driver attach.
 */
static void
ath_announce(struct ath_softc *sc)
{
#define	HAL_MODE_DUALBAND	(HAL_MODE_11A|HAL_MODE_11B)
	struct net_device *dev = &sc->sc_dev;
	struct ath_hal *ah = sc->sc_ah;
	u_int modes, cc;
	int i;

	if_printf(dev, "mac %d.%d phy %d.%d",
		ah->ah_macVersion, ah->ah_macRev,
		ah->ah_phyRev >> 4, ah->ah_phyRev & 0xf);
	/*
	 * Print radio revision(s).  We check the wireless modes
	 * to avoid falsely printing revs for inoperable parts.
	 * Dual-band radio revs are returned in the 5Ghz rev number.
	 */
	ath_hal_getcountrycode(ah, &cc);
	modes = ath_hal_getwirelessmodes(ah, cc);
	if ((modes & HAL_MODE_DUALBAND) == HAL_MODE_DUALBAND) {
		if (ah->ah_analog5GhzRev && ah->ah_analog2GhzRev)
			printk(" 5ghz radio %d.%d 2ghz radio %d.%d",
				ah->ah_analog5GhzRev >> 4,
				ah->ah_analog5GhzRev & 0xf,
				ah->ah_analog2GhzRev >> 4,
				ah->ah_analog2GhzRev & 0xf);
		else
			printk(" radio %d.%d", ah->ah_analog5GhzRev >> 4,
				ah->ah_analog5GhzRev & 0xf);
	} else
		printk(" radio %d.%d", ah->ah_analog5GhzRev >> 4,
			ah->ah_analog5GhzRev & 0xf);
	printk("\n");
	for (i = 0; i <= WME_AC_VO; i++) {
		struct ath_txq *txq = sc->sc_ac2q[i];
                    if_printf(dev, "Use hw queue %u for %s traffic\n",
                            txq->axq_qnum, ieee80211_wme_acnames[i]);
	}
        if_printf(dev, "Use hw queue %u for CAB traffic\n",
                sc->sc_cabq->axq_qnum);
        if_printf(dev, "Use hw queue %u for beacons\n", sc->sc_bhalq);
#undef HAL_MODE_DUALBAND
}



/*
 * Static (i.e. global) sysctls.  Note that the hal sysctls
 * are located under ours by sharing the setting for DEV_ATH.
 */
enum {
	DEV_ATH		= 9,			/* XXX known by hal */
};

static ctl_table ath_static_sysctls[] = {
#ifdef AR_DEBUG
	{ .ctl_name	= CTL_AUTO,
	   .procname	= "debug",
	  .mode		= 0644,
	  .data		= &ath_debug,
	  .maxlen	= sizeof(ath_debug),
	  .proc_handler	= proc_dointvec
	},
#endif
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "countrycode",
	  .mode		= 0444,
	  .data		= &ath_countrycode,
	  .maxlen	= sizeof(ath_countrycode),
	  .proc_handler	= proc_dointvec
	},
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "regdomain",
	  .mode		= 0444,
	  .data		= &ath_regdomain,
	  .maxlen	= sizeof(ath_regdomain),
	  .proc_handler	= proc_dointvec
	},
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "outdoor",
	  .mode		= 0444,
	  .data		= &ath_outdoor,
	  .maxlen	= sizeof(ath_outdoor),
	  .proc_handler	= proc_dointvec
	},
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "xchanmode",
	  .mode		= 0444,
	  .data		= &ath_xchanmode,
	  .maxlen	= sizeof(ath_xchanmode),
	  .proc_handler	= proc_dointvec
	},
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "dwelltime",
	  .mode		= 0644,
	  .data		= &ath_dwelltime,
	  .maxlen	= sizeof(ath_dwelltime),
	  .extra1	= &mindwelltime,
	  .extra2	= &maxint,
	  .proc_handler	= proc_dointvec_minmax
	},
	{ .ctl_name	= CTL_AUTO,
	  .procname	= "calibrate",
	  .mode		= 0644,
	  .data		= &ath_calinterval,
	  .maxlen	= sizeof(ath_calinterval),
	  .extra1	= &mincalibrate,
	  .extra2	= &maxint,
	  .proc_handler	= proc_dointvec_minmax
	},
	{ 0 }
};
static ctl_table ath_ath_table[] = {
	{ .ctl_name	= DEV_ATH,
	  .procname	= "ath",
	  .mode		= 0555,
	  .child	= ath_static_sysctls
	}, { 0 }
};
static ctl_table ath_root_table[] = {
	{ .ctl_name	= CTL_DEV,
	  .procname	= "dev",
	  .mode		= 0555,
	  .child	= ath_ath_table
	}, { 0 }
};
static struct ctl_table_header *ath_sysctl_header;

void
ath_sysctl_register(void)
{
	static int initialized = 0;

	if (!initialized) {
		ath_sysctl_header =
			register_sysctl_table(ath_root_table, 1);
		initialized = 1;
	}
}

void
ath_sysctl_unregister(void)
{
	if (ath_sysctl_header)
		unregister_sysctl_table(ath_sysctl_header);
}
#endif /* CONFIG_SYSCTL */


#ifdef HAS_CU_SOFTMAC
/*
 * serial port comm to T/R modules for soekris boards
 */
#include <asm-i386/io.h>
#include <linux/serial_reg.h>

/* @@@ARS@@@ */
void cu_softmac_ath_set_phocus_state(u_int16_t state,int16_t settle)
{
#define BOTH_EMPTY      (UART_LSR_TEMT | UART_LSR_THRE)
  u_int16_t val = 0x80 | state;
  volatile unsigned int status;
  // 400usec is default "settle time" for phocus
  if (0 > settle) settle = 400;
  outb((int)UART_MCR_RTS, 0x3f8 + UART_MCR);      /* toggle rts on */
  outb((int)val, 0x3f8 + UART_TX);                /* send the state value */
  do {
    status = inb(0x3f8 + UART_LSR);
  } while ( (status & BOTH_EMPTY) != BOTH_EMPTY);
  outb((int)0, 0x3f8 + UART_MCR);           /* toggle rts off */
  // need a delay for the time it takes the t/r modules to configure the DACs
  udelay(settle);
#undef BOTH_EMPTY
}

/*
 * 
 */
int
cu_softmac_phy_attach_ath(CU_SOFTMAC_PHY_HANDLE nfh,CU_SOFTMAC_MACLAYER_INFO* macinfo)
{
  struct ath_softc* sc = (struct ath_softc*)nfh;
  int result = 0;
  //printk("%s\n", __func__);
  
  cu_softmac_phy_detach_ath(nfh);
  
  /* lock the mac */
  write_lock(&(sc->sc_cu_softmac_mac_lock));
  
  /* get private copy of new MAC */
  sc->sc_cu_softmac_mac = cu_softmac_macinfo_get(macinfo);
  
  /* unlock the mac */
  write_unlock(&(sc->sc_cu_softmac_mac_lock));
  
  return result;
}

/*
 * 
 */
void
cu_softmac_phy_detach_ath(CU_SOFTMAC_PHY_HANDLE nfh)
{
  struct ath_softc *sc = (struct ath_softc*) nfh;

  //printk("%s\n", __func__);
  
  if (sc->sc_cu_softmac_mac == sc->sc_cu_softmac_defaultmac)
      return;

  write_lock(&(sc->sc_cu_softmac_mac_lock));

  cu_softmac_macinfo_free(sc->sc_cu_softmac_mac);
  sc->sc_cu_softmac_mac = sc->sc_cu_softmac_defaultmac;

  write_unlock(&(sc->sc_cu_softmac_mac_lock));
}

u_int64_t
cu_softmac_phy_get_time_ath(CU_SOFTMAC_PHY_HANDLE nfh)
{
    //printk("%s\n", __func__);

  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  struct ath_hal *ah = sc->sc_ah;

  return ath_hal_gettsf64(ah) - sc->sc_cu_softmac_zerotime;
}

void
cu_softmac_phy_set_time_ath(CU_SOFTMAC_PHY_HANDLE nfh,u_int64_t curtime)
{
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  struct ath_hal *ah = sc->sc_ah;
  u_int64_t mytsf = 0;
  mytsf = ath_hal_gettsf64(ah);
  sc->sc_cu_softmac_zerotime = mytsf - curtime;
}

void
cu_softmac_phy_schedule_work_asap_ath(CU_SOFTMAC_PHY_HANDLE nfh)
{
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  int needmark = 0;
  //printk(KERN_DEBUG "if_ath: scheduling worktq\n");
  ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq,&needmark);
  if (needmark) mark_bh(IMMEDIATE_BH);
}

struct sk_buff*
cu_softmac_phy_alloc_skb_ath(CU_SOFTMAC_PHY_HANDLE nfh,int datalen)
{
  struct sk_buff* newskb = 0;
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  /*
   * Allocate an sk_buff of the requested size with the kind of alignment
   * we'd like as well as with enough headroom for the extra couple of bytes
   * we have to pop onto the head of the packet in order to let it traverse
   * the stack without being altered by the Atheros hardware.
   */
  // XXX
  // verify the sizing/aligning junk...
  // check for "raw 802.11" mode
  newskb = ath_alloc_skb(datalen+sizeof(struct cu_softmac_header), sc->sc_cachelsz);
  skb_pull(newskb,sizeof(struct cu_softmac_header));
  return newskb;
}

void
cu_softmac_phy_free_skb_ath(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb)
{
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  if (in_irq()) {
    dev_kfree_skb_irq(skb);
  }
  else {
    dev_kfree_skb(skb);
  }
}

/*
 * Transmit a softmac frame.  On failure we reclaim the skbuff.
 */
int
cu_softmac_phy_sendpacket_ath(CU_SOFTMAC_PHY_HANDLE nfh,
			      int max_packets_inflight,
			      struct sk_buff* skb)
{
  int result = cu_softmac_phy_sendpacket_keepskbonfail_ath(nfh,max_packets_inflight,skb);
  if (0 != result) {
    dev_kfree_skb(skb);
    skb = 0;
  }
  return result;
}

/*
 * Transmit a softmac frame. On failure we leave the skbuff alone
 * so that the MAC layer can decide what it wants to do with
 * the packet.
 */
int
cu_softmac_phy_sendpacket_keepskbonfail_ath(CU_SOFTMAC_PHY_HANDLE nfh,
					    int max_packets_inflight,
					    struct sk_buff* skb)
{
  //struct net_device *dev = ic->ic_dev;
  struct ath_softc *sc = (struct ath_softc*) nfh;
  struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  struct ieee80211_node *ni = NULL;
  struct ath_buf *bf = NULL;
  //struct ieee80211_frame *wh;
  //struct ieee80211_cb *cb;
  struct ieee80211com *ic = &sc->sc_ic;
  int error = CU_SOFTMAC_PHY_SENDPACKET_OK;

  atomic_inc(&(sc->sc_cu_softmac_tx_packets_inflight));
  if (!(sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_RAW_MODE)) {
    skb = ath_cu_softmac_encapsulate(sc,skb);
  }
  if ((max_packets_inflight > 0) &&
      (max_packets_inflight < atomic_read(&(sc->sc_cu_softmac_tx_packets_inflight)))) {
    // Too many pending packets -- bail out...
    error = CU_SOFTMAC_PHY_SENDPACKET_ERR_TOOMANYPENDING;
    goto bad;
  }

  if ((dev->flags & IFF_RUNNING) == 0 || sc->sc_invalid) {
    DPRINTF(sc, ATH_DEBUG_XMIT,
	    "%s: discard, invalid %d flags %x\n",
	    __func__, sc->sc_invalid, dev->flags);
    sc->sc_stats.ast_tx_invalid++;
    error = CU_SOFTMAC_PHY_SENDPACKET_ERR_NETDOWN;
    goto bad;
  }

  if (sc->sc_cu_softmac_phocus_enable) {
      u_int16_t state = (u_int16_t)skb->cb[ATH_CU_SOFTMAC_CB_ANTENNA];
      if (state != sc->sc_cu_softmac_phocus_state) {
	  cu_softmac_ath_set_phocus_state(state, sc->sc_cu_softmac_phocus_settletime);
      }
  }

  /*
   * Grab a TX buffer and associated resources.
   */
  ATH_TXBUF_LOCK_BH(sc);
  bf = STAILQ_FIRST(&sc->sc_txbuf);
  if (bf != NULL)
    STAILQ_REMOVE_HEAD(&sc->sc_txbuf, bf_list);
  if (STAILQ_EMPTY(&sc->sc_txbuf))	{
    DPRINTF(sc, ATH_DEBUG_XMIT, "%s: stop queue\n", __func__);
    sc->sc_stats.ast_tx_qstop++;
    netif_stop_queue(dev);
  }
  ATH_TXBUF_UNLOCK_BH(sc);
  if (bf == NULL) {
    printk(KERN_DEBUG "ath_cusdr_sendpacket: discard, no xmit buf\n");
    //sc->sc_stats.ast_tx_nobufmgt++;
    error = CU_SOFTMAC_PHY_SENDPACKET_ERR_NOBUFFERS;
    goto bad;
  }
  
  /*
   * NB: the referenced node pointer is in the
   * control block of the sk_buff.  This is
   * placed there by ieee80211_mgmt_output because
   * we need to hold the reference with the frame.
   */
  //cb = (struct ieee80211_cb *)skb->cb;
  //ni = cb->ni;
  ni = ic->ic_bss;
  //error = ath_tx_start(dev, ni, bf, skb);

  error = ath_tx_raw_start(dev, ni, bf, skb);
  if (error == 0) {
    //sc->sc_stats.ast_tx_mgmt++;
    return 0;
  }
  /* fall thru... */
 bad:
  //if (ni && ni != ic->ic_bss)
  //ieee80211_free_node(ic, ni);
  // Decrement inflight packet count on failure
  atomic_dec(&(sc->sc_cu_softmac_tx_packets_inflight));
  if (!(sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_RAW_MODE)) {
      skb = cu_softmac_ath_decapsulate(sc,skb);
  }
  if (bf != NULL) {
    ATH_TXBUF_LOCK_BH(sc);
    STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
    ATH_TXBUF_UNLOCK_BH(sc);
  }
  //if (skb) {
  //dev_kfree_skb(skb);
  //}
  return error;
}

u_int32_t
cu_softmac_phy_get_duration_ath(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* skb)
{
  struct ath_softc *sc = (struct ath_softc*) nfh;
  struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;

  return ath_cu_softmac_packetduration(dev,skb);
}

static u_int32_t
cu_softmac_phy_get_txlatency_ath(CU_SOFTMAC_PHY_HANDLE nfh)
{
  struct ath_softc *sc = (struct ath_softc*) nfh;
  return sc->sc_cu_softmac_txlatency;
}

//
// The following functions are some atheros-specific things.
//

void
cu_softmac_ath_set_phyinfo_functions(CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
    // XXX lock?
    phyinfo->cu_softmac_phy_attach = cu_softmac_phy_attach_ath;
    phyinfo->cu_softmac_phy_detach = cu_softmac_phy_detach_ath;
    phyinfo->cu_softmac_phy_get_time = cu_softmac_phy_get_time_ath;
    phyinfo->cu_softmac_phy_set_time = cu_softmac_phy_set_time_ath;
    phyinfo->cu_softmac_phy_schedule_work_asap = cu_softmac_phy_schedule_work_asap_ath;
    phyinfo->cu_softmac_phy_alloc_skb = cu_softmac_phy_alloc_skb_ath;
    phyinfo->cu_softmac_phy_free_skb = cu_softmac_phy_free_skb_ath;
    phyinfo->cu_softmac_phy_sendpacket = cu_softmac_phy_sendpacket_ath;
    phyinfo->cu_softmac_phy_sendpacket_keepskbonfail = cu_softmac_phy_sendpacket_keepskbonfail_ath;
    phyinfo->cu_softmac_phy_get_duration = cu_softmac_phy_get_duration_ath;
    phyinfo->cu_softmac_phy_get_txlatency = cu_softmac_phy_get_txlatency_ath;
}

void 
cu_softmac_ath_set_cca_nf(CU_SOFTMAC_PHY_HANDLE nfh,u_int32_t ccanf) {
  struct ath_softc *sc = (struct ath_softc*) nfh;
  OS_REG_WRITE(sc->sc_ah,39012,ccanf);
}

void
cu_softmac_ath_set_cw(CU_SOFTMAC_PHY_HANDLE nfh,int cwmin,int cwmax) {
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  struct ath_hal *ah = sc->sc_ah;
  HAL_TXQ_INFO qi;
  memset(&qi, 0, sizeof(qi));
  //ath_tx_setup(sc, WME_AC_VO, HAL_WME_AC_VO)
  qi.tqi_subtype = HAL_WME_AC_VO;
  qi.tqi_qflags = TXQ_FLAG_TXEOLINT_ENABLE | TXQ_FLAG_TXDESCINT_ENABLE;
  qi.tqi_qflags |= 
    (TXQ_FLAG_TXOKINT_ENABLE | TXQ_FLAG_TXERRINT_ENABLE | TXQ_FLAG_BACKOFF_DISABLE);
  qi.tqi_cwmin = cwmin;
  qi.tqi_cwmax = cwmax;
  // XXX assuming we always use the WME_AC_VO queue for right now...
  ath_hal_settxqueueprops(ah,WME_AC_VO,&qi);
}

u_int32_t
cu_softmac_ath_get_slottime(CU_SOFTMAC_PHY_HANDLE nfh) {
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  struct ath_hal *ah = sc->sc_ah;
  return ath_hal_getslottime(ah);
}

void
cu_softmac_ath_set_slottime(CU_SOFTMAC_PHY_HANDLE nfh,u_int32_t slottime) {
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  struct ath_hal *ah = sc->sc_ah;
  ath_hal_setslottime(ah,slottime);
}

void cu_softmac_ath_set_options(CU_SOFTMAC_PHY_HANDLE nfh,u_int32_t options) {
  struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  sc->sc_cu_softmac_options = options;
  // XXX update based on new options
}


void
cu_softmac_ath_set_default_phy_props(CU_SOFTMAC_PHY_HANDLE nfh,
				     struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;

  // default to 1 Mb/s
  packet->cb[ATH_CU_SOFTMAC_CB_RATE] = 2;
  packet->cb[ATH_CU_SOFTMAC_CB_TXINTR] = 1;
  packet->cb[ATH_CU_SOFTMAC_CB_HAL_PKT_TYPE] = HAL_PKT_TYPE_NORMAL;
  packet->cb[ATH_CU_SOFTMAC_CB_HEADER_TYPE] = ATH_CU_SOFTMAC_CB_HEADER_REGULAR;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_RSSI] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_CHANNEL] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_ANTENNA] = 0; // zero is often "omni"
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF0] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF1] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF2] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF3] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF4] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF5] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF6] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_TSF7] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_BF0] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_BF1] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_BF2] = 0;
  packet->cb[ATH_CU_SOFTMAC_CB_RX_BF3] = 0;
}

void
cu_softmac_ath_set_tx_bitrate(CU_SOFTMAC_PHY_HANDLE nfh,
			      struct sk_buff* packet,unsigned char rate) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  packet->cb[ATH_CU_SOFTMAC_CB_RATE] = rate;
}

u_int8_t
cu_softmac_ath_get_rx_bitrate(CU_SOFTMAC_PHY_HANDLE nfh,
			      struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;

  return packet->cb[ATH_CU_SOFTMAC_CB_RATE];
}

void
cu_softmac_ath_require_txdone_interrupt(CU_SOFTMAC_PHY_HANDLE nfh,
					struct sk_buff* packet,
					int require_interrupt) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  packet->cb[ATH_CU_SOFTMAC_CB_TXINTR] = require_interrupt ? 1 : 0;
}

u_int64_t
cu_softmac_ath_get_rx_time(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  return *((u_int64_t*)(packet->cb+ATH_CU_SOFTMAC_CB_RX_TSF0));
}

u_int8_t
cu_softmac_ath_get_rx_rssi(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  return packet->cb[ATH_CU_SOFTMAC_CB_RX_RSSI];
}

u_int8_t
cu_softmac_ath_get_rx_channel(CU_SOFTMAC_PHY_HANDLE nfh,struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  return packet->cb[ATH_CU_SOFTMAC_CB_RX_RSSI];
}

u_int8_t
cu_softmac_ath_has_rx_crc_error(CU_SOFTMAC_PHY_HANDLE nfh,
				struct sk_buff* packet){
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  return packet->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR];
}

void
cu_softmac_ath_set_tx_antenna(CU_SOFTMAC_PHY_HANDLE nfh,
			      struct sk_buff* packet, u_int32_t state) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;
  packet->cb[ATH_CU_SOFTMAC_CB_ANTENNA] = (u_int8_t)state;
}

u_int32_t
cu_softmac_ath_get_rx_antenna(CU_SOFTMAC_PHY_HANDLE nfh,
			      struct sk_buff* packet) {
  //struct ath_softc *sc = (struct ath_softc*) nfh;
  //struct net_device* dev = &(sc->sc_dev);
  //struct ath_hal *ah = sc->sc_ah;

  return (u_int32_t)(packet->cb[ATH_CU_SOFTMAC_CB_ANTENNA]);
}

//
// Some "internal" softmac utility functions that smooth
// implementation of the external exported functions.
//
static struct sk_buff *
ath_alloc_skb(u_int size, u_int align)
{
	struct sk_buff *skb;
	u_int off;

	skb = dev_alloc_skb(size + align-1);
	if (skb != NULL) {
		off = ((unsigned long) skb->data) % align;
		if (off != 0)
			skb_reserve(skb, align - off);
	}
	return skb;
}

static unsigned char
ath_cu_softmac_tag_cb(struct ath_softc* sc,struct ath_desc* ds,struct sk_buff* skb) {
  struct ieee80211com *ic = &sc->sc_ic;
  unsigned char cbtype = 0;
  // RX timestamp
  u_int64_t tsf = 0;

  cbtype = ath_cu_softmac_getheadertype_cb(sc,skb);
  // tag the packet with the divined header type, bitrate, timestamp,
  // CRC error status, rssi...
  skb->cb[ATH_CU_SOFTMAC_CB_HEADER_TYPE] = cbtype;
  tsf = ath_hal_gettsf64(sc->sc_ah);
  if ((tsf & 0x7fff) < ds->ds_rxstat.rs_tstamp)
    tsf -= 0x8000;
  *((u_int64_t*)(skb->cb+ATH_CU_SOFTMAC_CB_RX_TSF0)) =
    (ds->ds_rxstat.rs_tstamp | (tsf &~ 0x7fff));
  
  // keep count of packets that contain crc errors
  //sc->sc_cu_softmac_rx_total++;
  if (ds->ds_rxstat.rs_status & HAL_RXERR_CRC) {
    skb->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR] = 1;
    //sc->sc_cu_softmac_rx_crcerror++;
  }
  else {
    skb->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR] = 0;
  }
  skb->cb[ATH_CU_SOFTMAC_CB_RATE] = sc->sc_hwmap[ds->ds_rxstat.rs_rate].ieeerate;
  skb->cb[ATH_CU_SOFTMAC_CB_RX_RSSI] = ds->ds_rxstat.rs_rssi;
  skb->cb[ATH_CU_SOFTMAC_CB_RX_CHANNEL] = ieee80211_mhz2ieee(ic->ic_ibss_chan->ic_freq,0);
  skb->cb[ATH_CU_SOFTMAC_CB_ANTENNA] = sc->sc_cu_softmac_phocus_state;

  return cbtype;
}

int
cu_softmac_ath_issoftmac(void *data,struct sk_buff* skb) {
  struct ath_softc *sc = (struct ath_softc *)data;
  int htype = ath_cu_softmac_getheadertype(sc,skb);
  return (CU_SOFTMAC_HEADER_UNKNOWN != htype);
}

static struct sk_buff*
ath_cu_softmac_encapsulate(struct ath_softc* sc,struct sk_buff* skb) {
  unsigned char* newheader = 0;
  struct cu_softmac_header* cush = 0;

  skb_cow(skb,sizeof(struct cu_softmac_header));
  newheader = skb_push(skb,sizeof(struct cu_softmac_header));
  memset(newheader,0,sizeof(struct cu_softmac_header));
  cush = (struct cu_softmac_header*) newheader;
  cush->wifictl0 = sc->sc_cu_softmac_wifictl0;
  cush->wifictl1 = sc->sc_cu_softmac_wifictl1;
  cush->wifiduration = 0x0000;
  cush->wifiaddr1_0 = 0xFF;
  skb->cb[ATH_CU_SOFTMAC_CB_HEADER_TYPE] = ATH_CU_SOFTMAC_CB_HEADER_REGULAR;
  skb->cb[ATH_CU_SOFTMAC_CB_HAL_PKT_TYPE] = HAL_PKT_TYPE_NORMAL;

  // Set some transmit attributes...
  skb->priority = WME_AC_VO;
  return skb;
}

struct sk_buff*
cu_softmac_ath_decapsulate(void *data, struct sk_buff* skb) {
  //struct ath_softc* sc = (struct ath_softc *)data;
  // strip the header off of the beginning, rip the CRC off of the end,
  // do the right thing w.r.t. packets that have CRC errors
  int haserrors = 0;

  // XXX use the getheadersize function?
  skb_pull(skb,sizeof(struct cu_softmac_header));
  skb_trim(skb, skb->len - IEEE80211_CRC_LEN);
  skb->mac.raw = skb->data;

  if (skb->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR]) {
    haserrors = 1;
  }

  return skb;
}

static int
ath_cu_softmac_handle_rx(struct net_device* dev,int intop) {
  int result = 0;
#define	PA2DESC(_sc, _pa) \
	((struct ath_desc *)((caddr_t)(_sc)->sc_desc + \
		((_pa) - (_sc)->sc_desc_daddr)))
#define	IS_CTL(wh) \
	((wh->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_CTL)
  //struct net_device *dev = (struct net_device *)data;
  struct ath_buf *bf;
  struct ath_softc *sc = dev->priv;
  //struct ieee80211com *ic = &sc->sc_ic;
  struct ath_hal *ah = sc->sc_ah;
  struct ath_desc *ds;
  struct sk_buff *skb;
  //struct ieee80211_node *ni;
  //struct ath_node *an;
  int len;
  //u_int phyerr;
  HAL_STATUS status;
  
  //printk(KERN_DEBUG "if_ath: in handle_rx %d\n",intop);
  DPRINTF(sc, ATH_DEBUG_RX_PROC, "%s\n", __func__);

  do {
    bf = STAILQ_FIRST(&sc->sc_rxbuf);
    if (bf == NULL) {		/* XXX ??? can this happen */
      printk("%s: no buffer (%s)\n", dev->name, __func__);
      break;
    }
    ds = bf->bf_desc;
    if (ds->ds_link == bf->bf_daddr) {
      /* NB: never process the self-linked entry at the end */
      break;
    }
    skb = bf->bf_skb;
    if (skb == NULL) {		/* XXX ??? can this happen */
      printk("%s: no skbuff (%s)\n", dev->name, __func__);
      continue;
    }
    /* XXX sync descriptor memory */
    /*
     * Must provide the virtual address of the current
     * descriptor, the physical address, and the virtual
     * address of the next descriptor in the h/w chain.
     * This allows the HAL to look ahead to see if the
     * hardware is done with a descriptor by checking the
     * done bit in the following descriptor and the address
     * of the current descriptor the DMA engine is working
     * on.  All this is necessary because of our use of
     * a self-linked list to avoid rx overruns.
     */
    status = ath_hal_rxprocdesc(ah, ds,
				bf->bf_daddr, PA2DESC(sc, ds->ds_link));
#ifdef AR_DEBUG
    if (sc->sc_debug & ATH_DEBUG_RECV_DESC)
      ath_printrxbuf(bf, status == HAL_OK); 
#endif
    if (status == HAL_EINPROGRESS)
      break;
    STAILQ_REMOVE_HEAD(&sc->sc_rxbuf, bf_list);
    
    // XXX need to decide what to do with jumbograms
    if (ds->ds_rxstat.rs_status != 0) {
	//DPRINTF(sc,ATH_DEBUG_ANY,"%s: RXERR: %hx DATALEN %hd\n",__func__,(short int)ds->ds_rxstat.rs_status,ds->ds_rxstat.rs_datalen);
      if (ds->ds_rxstat.rs_status & HAL_RXERR_CRC) {
	  //DPRINTF(sc,ATH_DEBUG_ANY,"%s: RXERR: %hx HAL_RXERR_CRC\n",__func__,(short int)ds->ds_rxstat.rs_status);
      }
      if (ds->ds_rxstat.rs_status & HAL_RXERR_FIFO) {
	  //DPRINTF(sc,ATH_DEBUG_ANY,"%s: RXERR: %hx HAL_RXERR_FIFO\n",__func__,(short int)ds->ds_rxstat.rs_status);
      }
      if (ds->ds_rxstat.rs_status & HAL_RXERR_PHY) {
	//sc->sc_stats.ast_rx_phyerr++;
	//phyerr = ds->ds_rxstat.rs_phyerr & 0x1f;
	//sc->sc_stats.ast_rx_phy[phyerr]++;
	  //DPRINTF(sc,ATH_DEBUG_ANY,"%s: RXERR: %hx HAL_RXERR_PHY %hx\n",__func__,(short int)ds->ds_rxstat.rs_status,(short int)ds->ds_rxstat.rs_phyerr);
      }
    }
    //rx_accept:
    /*
     * Sync and unmap the frame.  At this point we're
     * committed to passing the sk_buff somewhere so
     * clear buf_skb; this means a new sk_buff must be
     * allocated when the rx descriptor is setup again
     * to receive another frame.
     */
    len = ds->ds_rxstat.rs_datalen;
    bus_dma_sync_single(sc->sc_bdev,
			bf->bf_skbaddr, len, BUS_DMA_FROMDEVICE);
    if (0 < len) {
      ath_cu_softmac_tag_cb(sc,ds,skb);	
    }
    bus_unmap_single(sc->sc_bdev, bf->bf_skbaddr,
		     sc->sc_rxbufsize, BUS_DMA_FROMDEVICE);
    bf->bf_skb = NULL;
    
    /*
     * Normal receive.
     */
    if (0 < len) {
      // Handoff to the softmac
      if ((sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_ALLOW_CRCERR) || 
	  !(skb->cb[ATH_CU_SOFTMAC_CB_RX_CRCERR])) {
	skb_put(skb, len);
	*((struct ath_buf **)(skb->cb+ATH_CU_SOFTMAC_CB_RX_BF0)) = bf;
	if (ath_cu_softmac_rx(dev,skb,intop)) {
	  // Returning non-zero from here means that
	  // the softmac layer has not finished handling
	  // the packet. The softmac tasklet should execute.
	  result = 1;
	}
      }
      else {
	// Free packets with CRC errors
	dev_kfree_skb_any(skb);
      }
    }
    else {
      dev_kfree_skb_any(skb);
    }
    //rx_next:
    STAILQ_INSERT_TAIL(&sc->sc_rxbuf, bf, bf_list);
  } while (ath_rxbuf_init(sc, bf) == 0);
  
#undef IS_CTL
#undef PA2DESC
  return result;
}

static void
ath_cu_softmac_rx_tasklet(TQUEUE_ARG data) {
  struct net_device *dev = (struct net_device *)data;
  struct ath_softc* sc = dev->priv;
  int goagain = 0; 
  //printk(KERN_DEBUG "if_ath: in rx_tasklet\n");
  goagain = ath_cu_softmac_handle_rx(dev,0);
  if (goagain) {
    int needmark = 0;
    ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq,&needmark);
    if (needmark) {
      mark_bh(IMMEDIATE_BH);
    }
  }
}

static int
ath_cu_softmac_rx(struct net_device* dev,struct sk_buff* skb,int intop) 
{
    struct ath_softc* sc = dev->priv;
    int result = 0;
    void *macpriv;
    int rxresult;
    
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
    read_lock(&(sc->sc_cu_softmac_mac_lock));
#else
    if (!read_trylock(&(sc->sc_cu_softmac_mac_lock))) {
	dev_kfree_skb_any(skb);
	return 0;
    }
#endif

    /* if in raw mode, packets are passed to the MAC unchanged
     * otherwise, softmac packets get decapsulated and others are dropped
     */
    if ( !(sc->sc_cu_softmac_options & CU_SOFTMAC_ATH_RAW_MODE) ) {
	if (cu_softmac_ath_issoftmac(sc,skb)) {
	    //printk("%s got softmac packet!\n", __func__);
	    skb = cu_softmac_ath_decapsulate(sc, skb);
	} else {
	    /* not in raw mode and not softmac, discard */
	    dev_kfree_skb_any(skb);
	    read_unlock(&(sc->sc_cu_softmac_mac_lock));
	    return 0;
	}
    } else {
	//printk("%s got non-softmac packet!\n", __func__);
    }

    macpriv = sc->sc_cu_softmac_mac->mac_private;
    rxresult = (sc->sc_cu_softmac_mac->cu_softmac_mac_packet_rx)(macpriv,skb,intop);
    if (CU_SOFTMAC_MAC_NOTIFY_OK == rxresult) {
	//printk(KERN_DEBUG "SoftMAC: packet handled -- not running again\n");
    }
    else if (CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN == rxresult) {
	//printk(KERN_DEBUG "SoftMAC: packet not finished -- running again\n");
	result = 1;
    }
    else {
	/* Something went wrong -- free the packet and move on. */
	printk(KERN_DEBUG "SoftMAC: packet handling failed -- nuking\n");
	dev_kfree_skb_any(skb);
    }

    read_unlock(&(sc->sc_cu_softmac_mac_lock));
    return result;
}

static int
ath_cu_softmac_packetduration(struct net_device* dev,struct sk_buff* skb) {
  int pktduration = 0;
  int rix = 0;
  struct ath_softc* sc = dev->priv;
  struct ath_hal *ah = sc->sc_ah;
  const HAL_RATE_TABLE* rt = 0;
  if (skb) {
    // Get length, bitrate, tack on the "built in" tx latency...
    //sc->sc_cu_softmac_tdma_txlatency
    rix = sc->sc_rixmap[skb->cb[ATH_CU_SOFTMAC_CB_RATE] & IEEE80211_RATE_VAL];
    if (0xFF == rix) {
      rix = 0;
    }
    rt = sc->sc_currates;
    pktduration = ath_hal_computetxtime(ah,rt,skb->len,rix,AH_TRUE);
  }

  return pktduration;
}

static int
ath_tx_raw_start(struct net_device *dev, struct ieee80211_node *ni, struct ath_buf *bf,
    struct sk_buff *skb)
{
#define	MIN(a,b)	((a) < (b) ? (a) : (b))
	struct ath_softc *sc = dev->priv;
	//struct ieee80211com *ic = &sc->sc_ic;
	struct ath_hal *ah = sc->sc_ah;
	//int iswep, ismcast;
	int keyix, hdrlen, pktlen, try0;
	u_int8_t rix, txrate, ctsrate;
	//u_int8_t cix = 0xff;		/* NB: silence compiler */
	struct ath_desc *ds;
	struct ath_txq *txq;
	//struct ieee80211_frame *wh;
	//u_int subtype, flags, ctsduration;
	u_int flags, ctsduration;
	HAL_PKT_TYPE atype;
	const HAL_RATE_TABLE *rt;
	HAL_BOOL shortPreamble;
	struct ath_node *an;

	//wh = (struct ieee80211_frame *) skb->data;
	//iswep = wh->i_fc[1] & IEEE80211_FC1_WEP;
	//ismcast = IEEE80211_IS_MULTICAST(wh->i_addr1);
	//hdrlen = ieee80211_anyhdrsize(wh);
	hdrlen = 0;
	pktlen = skb->len;

	keyix = HAL_TXKEYIX_INVALID;
	// XXX need this?
	pktlen += IEEE80211_CRC_LEN;

	/*
	 * Load the DMA map so any coalescing is done.  This
	 * also calculates the number of descriptors we need.
	 */
	bf->bf_skbaddr = bus_map_single(sc->sc_bdev,
		skb->data, pktlen, BUS_DMA_TODEVICE);
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: skb %p [data %p len %u] skbaddr %x\n",
		__func__, skb, skb->data, skb->len, bf->bf_skbaddr);
	bf->bf_skb = skb;
	bf->bf_node = ni;

	/* setup descriptors */
	ds = bf->bf_desc;
	rt = sc->sc_currates;
	KASSERT(rt != NULL, ("no rate table, mode %u", sc->sc_curmode));

	/*
	 * NB: the 802.11 layer marks whether or not we should
	 * use short preamble based on the current mode and
	 * negotiated parameters.
	 */
	// Always use short preamble
	shortPreamble = AH_TRUE;

	an = ATH_NODE(ni);
	/*
	 * Calculate Atheros packet type from IEEE80211 packet header,
	 * setup for rate calculations, and select h/w transmit queue.
	 */
	// XXX not sure which of these packet types is appropriate
	//atype = HAL_PKT_TYPE_ATIM;
	//atype = HAL_PKT_TYPE_NORMAL;	/* XXX */
	//atype = HAL_PKT_TYPE_PSPOLL;	/* stop setting of duration */
	//atype = HAL_PKT_TYPE_BEACON;
	//atype = HAL_PKT_TYPE_PROBE_RESP;
	//atype = HAL_PKT_TYPE_PIFS;
	//atype = 16;
	atype = skb->cb[ATH_CU_SOFTMAC_CB_HAL_PKT_TYPE];
	try0 = ATH_TXMAXTRY;

	// XXX figure out txrate to set...
	//rix = 0;			/* XXX lowest rate */
	//txrate = an->an_tx_mgtrate;
	//if (shortPreamble)
	//txrate = an->an_tx_mgtratesp;
	//else
	//txrate = an->an_tx_mgtrate;

	/*
	 * Data frames; consult the rate control module.
	 */
	// XXX HAS_CU_SDR for now just call the findrate function...
	// As long as you set the rate with iwconfig this should result
	// in a constant bitrate.
	//ath_rate_findrate(sc, an, shortPreamble, skb->len,
	//&rix, &try0, &txrate);
	// Set bitrate based on skbuff scratch space. This uses the
	// 802.11-style unit of "512Kb/s," i.e. set it to twice
	// the desired bitrate in megabits. Setting the value
        // to 0 or something undefined in the current mode should
	// get you the lowest bitrate in the available set.
	rix = sc->sc_rixmap[skb->cb[ATH_CU_SOFTMAC_CB_RATE] & IEEE80211_RATE_VAL];
	if (0xFF == rix) {
	    rix = 0;
	}
        txrate = sc->sc_currates->info[rix].rateCode;

	// XXX figure out txqueue to use -- I think probably
	// the highest rate queue for now, but should let this
	// get set on a per-packet basis.
	/*
	 * Default all non-QoS traffic to the background queue.
	 */
	//if (wh->i_fc[0] & IEEE80211_FC0_SUBTYPE_QOS) {
	  /* XXX validate skb->priority */
	  //txq = sc->sc_ac2q[skb->priority];
	//} else
	// txq = sc->sc_ac2q[WME_AC_BK];
	/* NB: force all management frames to highest queue */
	txq = sc->sc_ac2q[skb->priority];

	/*
	 * Calculate miscellaneous flags.
	 */
	flags = HAL_TXDESC_CLRDMASK | HAL_TXDESC_NOACK;
	ctsrate = 0;
	ctsduration = 0;

	/* 
	 * Determine if a tx interrupt should be generated for
	 * this descriptor.  We take a tx interrupt to reap
	 * descriptors when the h/w hits an EOL condition or
	 * when the descriptor is specifically marked to generate
	 * an interrupt.  We periodically mark descriptors in this
	 * way to insure timely replenishing of the supply needed
	 * for sending frames.  Defering interrupts reduces system
	 * load and potentially allows more concurrent work to be
	 * done but if done to aggressively can cause senders to
	 * backup.
	 *
	 * NB: use >= to deal with sc_txintrperiod changing
	 *     dynamically through sysctl.
	 */
	if ((++txq->axq_intrcnt >= sc->sc_txintrperiod) ||
	    skb->cb[ATH_CU_SOFTMAC_CB_TXINTR]) {
		flags |= HAL_TXDESC_INTREQ;
		txq->axq_intrcnt = 0;
	}

	/*
	 * Formulate first tx descriptor with tx controls.
	 */
	/* XXX check return value? */
	ath_hal_setuptxdesc(ah, ds
		, pktlen		/* packet length */
		, hdrlen		/* header length */
		, atype			/* Atheros packet type */
		, MIN(ni->ni_txpower,60)/* txpower */
		, txrate, try0		/* series 0 rate/tries */
		, keyix			/* key cache index */
		, sc->sc_txantenna	/* antenna mode */
		, flags			/* flags */
		, ctsrate		/* rts/cts rate */
		, ctsduration		/* rts/cts duration */
	);

	ds->ds_link = 0;
	ds->ds_data = bf->bf_skbaddr;
	ath_hal_filltxdesc(ah, ds
		, skb->len		/* segment length */
		, AH_TRUE		/* first segment */
		, AH_TRUE		/* last segment */
		, ds			/* first descriptor */
	);
	DPRINTF(sc, ATH_DEBUG_XMIT, "%s: Q%d: %08x %08x %08x %08x %08x %08x\n",
	    __func__, txq->axq_qnum, ds->ds_link, ds->ds_data,
	    ds->ds_ctl0, ds->ds_ctl1, ds->ds_hw[0], ds->ds_hw[1]);

	/*
	 * Insert the frame on the outbound list and
	 * pass it on to the hardware.
	 */
	ATH_TXQ_LOCK_BH(txq);
	ATH_TXQ_INSERT_TAIL(txq, bf, bf_list);
	DPRINTF(sc, ATH_DEBUG_TX_PROC, "%s: txq depth = %d\n",
		__func__, txq->axq_depth);
	if (txq->axq_link == NULL) {
		ath_hal_puttxbuf(ah, txq->axq_qnum, bf->bf_daddr);
		DPRINTF(sc, ATH_DEBUG_XMIT, "%s: TXDP[%u] = %p (%p)\n",
			__func__,
		    txq->axq_qnum, (caddr_t)bf->bf_daddr, bf->bf_desc);
	} else {
		*txq->axq_link = bf->bf_daddr;
		DPRINTF(sc, ATH_DEBUG_XMIT, "%s: link[%u](%p)=%p (%p)\n",
			__func__,
		    txq->axq_qnum, txq->axq_link,
		    (caddr_t)bf->bf_daddr, bf->bf_desc);
	}
	txq->axq_link = &ds->ds_link;
	ATH_TXQ_UNLOCK_BH(txq);
	ath_hal_txstart(ah, txq->axq_qnum);
	dev->trans_start = jiffies;
	return 0;
#undef MIN
}

static int
ath_cu_softmac_handle_txdone(struct net_device* dev, int intop) {
  struct ath_buf* bf = 0;
  struct ath_softc* sc = dev->priv;
  struct ath_txq* txq = 0;
  struct ath_desc *ds = 0;
  struct sk_buff* skb = 0;
  struct ath_hal *ah = sc->sc_ah;
  void* macpriv = 0;
  int i;
  int result = 0;
  int status;
  macpriv = sc->sc_cu_softmac_mac->mac_private;
  /*
   * Process each active queue.
   */
  /* XXX faster to read ISR_S0_S and ISR_S1_S to determine q's? */
  for (i = 0; i < HAL_NUM_TX_QUEUES; i++) {
    if (ATH_TXQ_SETUP(sc, i)) {
      //ath_tx_processq(sc, &sc->sc_txq[i]);
      txq = &sc->sc_txq[i];

      for (;;) {
	ATH_TXQ_LOCK(txq);
	txq->axq_intrcnt = 0;	/* reset periodic desc intr count */
	bf = STAILQ_FIRST(&txq->axq_q);
	if (bf == NULL) {
	  txq->axq_link = NULL;
	  ATH_TXQ_UNLOCK(txq);
	  break;
	}
	ds = bf->bf_desc;		/* NB: last decriptor */
	status = ath_hal_txprocdesc(ah, ds);
#ifdef AR_DEBUG
	if (sc->sc_debug & ATH_DEBUG_XMIT_DESC)
	  ath_printtxbuf(bf, status == HAL_OK);
#endif
	if (status == HAL_EINPROGRESS) {
	  ATH_TXQ_UNLOCK(txq);
	  break;
	}
	ATH_TXQ_REMOVE_HEAD(txq, bf_list);
	ATH_TXQ_UNLOCK(txq);
	bus_unmap_single(sc->sc_bdev,
			 bf->bf_skbaddr, bf->bf_skb->len, BUS_DMA_TODEVICE);
	// Packet done, decrement the "in flight" counter
	atomic_dec(&(sc->sc_cu_softmac_tx_packets_inflight));
	skb = bf->bf_skb;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
	read_lock(&(sc->sc_cu_softmac_mac_lock));
	if (1) {
#else
	if (read_trylock(&(sc->sc_cu_softmac_mac_lock))) {
#endif
	  // XXX make a dummy MAC layer to avoid this check?
	  if (sc->sc_cu_softmac_mac->cu_softmac_mac_packet_tx_done) {
	    int txdoneresult = (sc->sc_cu_softmac_mac->cu_softmac_mac_packet_tx_done)(macpriv,skb,intop);
	    if (CU_SOFTMAC_MAC_NOTIFY_OK == txdoneresult) {
	      result = 0;
	    }
	    else if (CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN == txdoneresult) {
	      result = 1;
	    }
	    else {
	      /*
	       * Something went wrong -- free the packet and move on.
	       */
	      dev_kfree_skb(skb);
	      skb = 0;
	      result = 0;
	    }
	  }
	  else {
	    /*
	     * No hook function set -- free the packet and move on.
	     */
	    dev_kfree_skb(skb);
	    skb = 0;
	    result = 0;
	  }
	  read_unlock(&(sc->sc_cu_softmac_mac_lock));
	}
	else {
	  // unable to get lock -- free packet and move on
	  dev_kfree_skb(skb);
	  skb = 0;
	  result = 0;
	}
	// bf->bf_skb is now owned by the softmac or dead. Pull it out of the
	// tx buffer and reallocate.
	bf->bf_skb = NULL;
	bf->bf_node = NULL;
	
	ATH_TXBUF_LOCK(sc);
	STAILQ_INSERT_TAIL(&sc->sc_txbuf, bf, bf_list);
	ATH_TXBUF_UNLOCK(sc);
      }
    }
  }

  return result;
}

static void
ath_cu_softmac_txdone_tasklet(TQUEUE_ARG data) {
  struct net_device *dev = (struct net_device *)data;
  struct ath_softc* sc = dev->priv;
  int goagain = 0;
  //printk(KERN_DEBUG "if_ath: in txdone_tasklet\n");
  goagain = ath_cu_softmac_handle_txdone(dev,0);
  if (goagain) {
    int needmark = 0;
    ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq,&needmark);
    if (needmark) {
      mark_bh(IMMEDIATE_BH);
    }
  }
}

static void
ath_cu_softmac_work_tasklet(TQUEUE_ARG data) {
  struct net_device *dev = (struct net_device *)data;
  struct ath_softc *sc = dev->priv;
  void* macpriv = 0;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
  read_lock(&(sc->sc_cu_softmac_mac_lock));
#else
  if (!read_trylock(&(sc->sc_cu_softmac_mac_lock))) {
    return;
  }
#endif

  // See if we've got a "hook" function set -- run it if we do
  //printk(KERN_DEBUG "In ath_cu_softmac_work_tasklet\n");
  macpriv = sc->sc_cu_softmac_mac->mac_private;
  if (sc->sc_cu_softmac_mac->cu_softmac_mac_work) {
    int workresult = CU_SOFTMAC_MAC_NOTIFY_OK;
    int needmark = 0;
    //printk(KERN_DEBUG "In ath_cu_softmac_work_tasklet: have a workfunc!\n");
    workresult = (sc->sc_cu_softmac_mac->cu_softmac_mac_work)(macpriv,0);
    if (CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN == workresult) {
      //printk(KERN_DEBUG "In ath_cu_softmac_work_tasklet: rescheduling!\n");
      ATH_SCHEDULE_TQUEUE(&sc->sc_cu_softmac_worktq,&needmark);
      if (needmark) {
	mark_bh(IMMEDIATE_BH);
      }
    }
  }
  read_unlock(&(sc->sc_cu_softmac_mac_lock));
}

// XXX beat the header stuff into shape...
// returns length of header or -1 if unknown packet type
static int
ath_cu_softmac_getheaderlen(struct ath_softc* sc,struct sk_buff* skb) {
  int result = -1;
  int htype = ath_cu_softmac_getheadertype(sc,skb);

  switch (htype) {
  case CU_SOFTMAC_HEADER_REGULAR:
    result = sizeof(struct cu_softmac_header);
    break;
  default:
    result = -1;
    break;
  }

  return result;
}

// returns CU_SOFTMAC_HEADER_* variable
static int
ath_cu_softmac_getheadertype(struct ath_softc* sc,struct sk_buff* skb) {
  int result = CU_SOFTMAC_HEADER_UNKNOWN;

  if ((sc->sc_cu_softmac_wifictl0 == skb->data[0]) &&
      (sc->sc_cu_softmac_wifictl1 == skb->data[1])) {
    result = CU_SOFTMAC_HEADER_REGULAR;
  }
  else {
    result = CU_SOFTMAC_HEADER_UNKNOWN;
  }

  return result;
}

static unsigned char
ath_cu_softmac_getheadertype_cb(struct ath_softc* sc,struct sk_buff* skb) {
  int result = ATH_CU_SOFTMAC_CB_HEADER_UNKNOWN;

  if ((sc->sc_cu_softmac_wifictl0 == skb->data[0]) &&
      (sc->sc_cu_softmac_wifictl1 == skb->data[1])) {
    result = ATH_CU_SOFTMAC_CB_HEADER_REGULAR;
  }
  else {
    result = ATH_CU_SOFTMAC_CB_HEADER_UNKNOWN;
  }

  return result;
}

static void*
cu_softmac_layer_new_instance_athphy(void *layer_private)
{
    struct ath_softc *sc = layer_private;
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo;

    // XXX does madwifi support multiple instances? one for now...
    phyinfo = sc->sc_cu_softmac_phy;
    if (!phyinfo) {
	/* setup phyinfo */
	phyinfo = cu_softmac_phyinfo_alloc();
	if (phyinfo) { 
	    sc->sc_cu_softmac_phy = phyinfo;
	    
	    strncpy(phyinfo->name, "athphy0"/*sc->sc_dev.name*/, CU_SOFTMAC_NAME_SIZE);
	    phyinfo->layer = &the_athphy;
	    phyinfo->phy_private = sc;
	    cu_softmac_ath_set_phyinfo_functions(phyinfo);

	    /* register with softmac */
	    cu_softmac_phyinfo_register(phyinfo);

	    /* create softmac specific procfs entries */
	    INIT_LIST_HEAD(&sc->sc_cu_softmac_procfs_data);
	    ath_cu_softmac_athphy_make_procfs(sc);
	    
	    /* an instance doesn't hold a reference to itself */
	    cu_softmac_phyinfo_free(phyinfo);
	}
    }
    return phyinfo;
}


/* Called when a Atheros CU_SOFTMAC_PHYLAYER_INFO structure is being deallocated */
static void
cu_softmac_layer_free_instance_athphy(void *layer_private, void *phy)
{
    CU_SOFTMAC_PHYLAYER_INFO *phyinfo = phy;
    struct ath_softc *sc = phyinfo->phy_private;
    if (phyinfo == sc->sc_cu_softmac_phy)
	cu_softmac_phy_detach_ath(sc);

    /* delete softmac specific procfs entries */
    ath_cu_softmac_athphy_delete_procfs(sc);
}

/*
**
** softmac 80211 mac
**
*/

static int
ath_cu_softmac_athmac_start(struct sk_buff* skb, struct net_device *dev)
{
    //printk("%s\n", __func__);
    int ret;
    struct ath_softc *sc = dev->priv;
    ret = cu_softmac_mac_packet_tx_ath(sc, skb, 0);
    return ret;
}

static int
cu_softmac_mac_packet_tx_ath(void *me, struct sk_buff* skb, int intop)
{
    //printk("%s\n", __func__);
    struct ath_softc* sc = (struct ath_softc*)me;
    //struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    ath_start(skb, &sc->sc_dev);
    return CU_SOFTMAC_MAC_NOTIFY_OK;
}

static int
cu_softmac_mac_packet_rx_ath(void *me, struct sk_buff* skb, int intop)
{
    //printk("%s\n", __func__);
    struct ath_softc* sc = (struct ath_softc*)me;
    //struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    struct ath_buf *bf = *((struct ath_buf **)(skb->cb+ATH_CU_SOFTMAC_CB_RX_BF0));

    if (!bf) {
	printk("%s error bf == 0\n", __func__);
	dev_kfree_skb(skb);
	return CU_SOFTMAC_MAC_NOTIFY_OK;
    }

    struct ieee80211_node *ni;
    struct ieee80211com *ic = &sc->sc_ic;
    struct ath_node *an;
    struct ath_desc *ds = bf->bf_desc;
    int type;
    
    sc->sc_stats.ast_ant_rx[ds->ds_rxstat.rs_antenna]++;
    
    if (skb->len < IEEE80211_ACK_LEN) {
	DPRINTF(sc, ATH_DEBUG_RECV,
		"%s: runt packet %d\n", __func__, skb->len);
	sc->sc_stats.ast_rx_tooshort++;
	dev_kfree_skb(skb);
	return CU_SOFTMAC_MAC_NOTIFY_OK;
    }
    skb->protocol = ETH_P_CONTROL;		/* XXX */

    /*
     * At this point we have no need for error frames
     * that aren't crypto problems since we're done
     * with capture.
     */
    if (ds->ds_rxstat.rs_status &~
	(HAL_RXERR_DECRYPT|HAL_RXERR_MIC)) {
	dev_kfree_skb(skb);
	return CU_SOFTMAC_MAC_NOTIFY_OK;
    }
    /*
     * From this point on we assume the frame is at least
     * as large as ieee80211_frame_min; verify that.
     */
    if (skb->len < IEEE80211_MIN_LEN) {
	DPRINTF(sc, ATH_DEBUG_RECV, "%s: short packet %d\n",
		__func__, skb->len);
	sc->sc_stats.ast_rx_tooshort++;
	dev_kfree_skb(skb);
	return CU_SOFTMAC_MAC_NOTIFY_OK;
    }

    /*
     * Normal receive.
     */
    if (IFF_DUMPPKTS(sc, ATH_DEBUG_RECV)) {
	ieee80211_dump_pkt(skb->data, skb->len,
			   sc->sc_hwmap[ds->ds_rxstat.rs_rate].ieeerate,
			   ds->ds_rxstat.rs_rssi);
    }

    skb_trim(skb, skb->len - IEEE80211_CRC_LEN);

    /*
     * Locate the node for sender, track state, and then
     * pass the (referenced) node up to the 802.11 layer
     * for its use.
     */
    ni = ieee80211_find_rxnode(ic,
			       (struct ieee80211_frame_min *)skb->data);

    /*
     * Track rx rssi and do any rx antenna management.
     */
    an = ATH_NODE(ni);
    ATH_RSSI_LPF(an->an_avgrssi, ds->ds_rxstat.rs_rssi);
    if (sc->sc_diversity) {
	/*
	 * When using fast diversity, change the default rx
	 * antenna if diversity chooses the other antenna 3
	 * times in a row.
	 */
	if (sc->sc_defant != ds->ds_rxstat.rs_antenna) {
	    if (++sc->sc_rxotherant >= 3)
		ath_setdefantenna(sc,
				  ds->ds_rxstat.rs_antenna);
	} else
	    sc->sc_rxotherant = 0;
    }

    /*
     * Send frame up for processing.
     */
    type = ieee80211_input(ic, skb, ni,
			   ds->ds_rxstat.rs_rssi, ds->ds_rxstat.rs_tstamp);

    /*
     * Reclaim node reference.
     */
    ieee80211_free_node(ni);

    return CU_SOFTMAC_MAC_NOTIFY_OK;
}

static int
cu_softmac_mac_detach_ath(void *me)
{
    struct ath_softc *sc = (struct ath_softc*)me;
    struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    //printk("%s\n", __func__);

    if (inst->phyinfo == inst->defaultphy)
	return 0;

    write_lock(&(inst->lock));

    cu_softmac_phyinfo_free(inst->phyinfo);
    inst->phyinfo = inst->defaultphy;

    write_unlock(&(inst->lock));
    return 0;
}

static int
cu_softmac_mac_attach_ath(void *me, CU_SOFTMAC_PHYLAYER_INFO* phyinfo)
{
  struct ath_softc* sc = (struct ath_softc*)me;
  struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
  int result = 0;
  
  //printk("%s\n", __func__);
  cu_softmac_mac_detach_ath(sc);
  
  /* lock the mac */
  write_lock(&(inst->lock));
  
  /* get reference to PHY */
  inst->phyinfo = cu_softmac_phyinfo_get(phyinfo);
  
  /* unlock the mac */
  write_unlock(&(inst->lock));
  
  return result;
}

static int
cu_softmac_mac_set_rx_func_ath(void *me, CU_SOFTMAC_MAC_RX_FUNC rxfunc, void *rxpriv)
{
    //printk("%s\n", __func__);
    struct ath_softc* sc = (struct ath_softc*)me;
    struct ieee80211com *ic = &sc->sc_ic;
    struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    int result = 0;
    write_lock(&(inst->lock));
    
    ic->ic_softmac_rxfunc = rxfunc;
    ic->ic_softmac_rxpriv = rxpriv;

    write_unlock(&(inst->lock));
    
    return result;
}

static void
cu_softmac_ath_set_macinfo_functions(CU_SOFTMAC_MACLAYER_INFO *macinfo)
{
    macinfo->cu_softmac_mac_packet_tx = cu_softmac_mac_packet_tx_ath;
    //macinfo->cu_softmac_mac_packet_tx_done = cu_softmac_mac_packet_tx_done_ath;
    macinfo->cu_softmac_mac_packet_rx = cu_softmac_mac_packet_rx_ath;
    //macinfo->cu_softmac_mac_work = cu_softmac_mac_work_ath;
    macinfo->cu_softmac_mac_attach = cu_softmac_mac_attach_ath;
    macinfo->cu_softmac_mac_detach = cu_softmac_mac_detach_ath;
    macinfo->cu_softmac_mac_set_rx_func = cu_softmac_mac_set_rx_func_ath;
    //macinfo->cu_softmac_mac_set_unload_notify_func = cu_softmac_mac_set_unload_notify_func_ath;
}

static void*
cu_softmac_layer_new_instance_athmac(void *layer_private)
{
    struct ath_softc *sc = (struct ath_softc *)layer_private;
    struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    struct ieee80211com *ic = &sc->sc_ic;
    struct net_device *dev = ic->ic_dev;    
    CU_SOFTMAC_MACLAYER_INFO *macinfo;

    if (!inst) {
	printk("%s error: !inst\n", __func__);
	return 0;
    }
    
    macinfo = inst->macinfo;
    if (!macinfo) {
	/* setup macinfo */
	macinfo = cu_softmac_macinfo_alloc();
	if (macinfo) {
	    inst->macinfo = macinfo;

	    strncpy(macinfo->name, "athmac0", CU_SOFTMAC_NAME_SIZE);
	    macinfo->layer = &the_athmac;
	    macinfo->mac_private = sc;
	    cu_softmac_ath_set_macinfo_functions(macinfo);
	    
	    /* register with softmac */
	    cu_softmac_macinfo_register(macinfo);
	    cu_softmac_macinfo_free(macinfo);
	}
	dev->hard_start_xmit = ath_cu_softmac_athmac_start;
    }
    return macinfo;
}

/* Called when a Atheros CU_SOFTMAC_MACLAYER_INFO structure is being deallocated */
static void
cu_softmac_layer_free_instance_athmac(void *layer_private, void *mac)
{
    CU_SOFTMAC_MACLAYER_INFO *macinfo = mac;
    struct ath_softc *sc = (struct ath_softc *)macinfo->mac_private;
    struct cu_softmac_athmac_instance *inst = sc->sc_cu_softmac_mac_inst;
    if (macinfo == inst->macinfo)
	cu_softmac_mac_detach_ath(sc);
}

static void
ath_cu_softmac_register(struct ath_softc* sc)
{
    /* register the athphy layer with softmac */
    strncpy(the_athphy.name, "athphy", CU_SOFTMAC_NAME_SIZE);
    the_athphy.cu_softmac_layer_new_instance = cu_softmac_layer_new_instance_athphy;
    the_athphy.cu_softmac_layer_free_instance = cu_softmac_layer_free_instance_athphy;
    the_athphy.layer_private = sc;

    cu_softmac_layer_register(&the_athphy);

    /* register the athmac layer with softmac */
    strncpy(the_athmac.name, "athmac", CU_SOFTMAC_NAME_SIZE);
    the_athmac.cu_softmac_layer_new_instance = cu_softmac_layer_new_instance_athmac;
    the_athmac.cu_softmac_layer_free_instance = cu_softmac_layer_free_instance_athmac;
    the_athmac.layer_private = sc;

    cu_softmac_layer_register(&the_athmac);
}

static void
ath_cu_softmac_unregister(struct ath_softc* sc)
{
    cu_softmac_layer_unregister(&the_athphy);
    cu_softmac_layer_unregister(&the_athmac);
}

EXPORT_SYMBOL(cu_softmac_ath_set_phyinfo_functions);

EXPORT_SYMBOL(cu_softmac_ath_set_cca_nf);
EXPORT_SYMBOL(cu_softmac_ath_set_cw);
EXPORT_SYMBOL(cu_softmac_ath_get_slottime);
EXPORT_SYMBOL(cu_softmac_ath_set_slottime);
EXPORT_SYMBOL(cu_softmac_ath_set_options);

EXPORT_SYMBOL(cu_softmac_ath_decapsulate);
EXPORT_SYMBOL(cu_softmac_ath_issoftmac);

EXPORT_SYMBOL(cu_softmac_ath_set_default_phy_props);
EXPORT_SYMBOL(cu_softmac_ath_set_tx_bitrate);
EXPORT_SYMBOL(cu_softmac_ath_get_rx_bitrate);
EXPORT_SYMBOL(cu_softmac_ath_require_txdone_interrupt);
EXPORT_SYMBOL(cu_softmac_ath_get_rx_time);
EXPORT_SYMBOL(cu_softmac_ath_has_rx_crc_error);
EXPORT_SYMBOL(cu_softmac_ath_get_rx_rssi);
EXPORT_SYMBOL(cu_softmac_ath_get_rx_channel);
EXPORT_SYMBOL(cu_softmac_ath_set_tx_antenna);
EXPORT_SYMBOL(cu_softmac_ath_get_rx_antenna);
EXPORT_SYMBOL(cu_softmac_ath_set_phocus_state);
#endif
