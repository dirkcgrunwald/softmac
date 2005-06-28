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

#ifndef _CU_SOFTMAC_API_H
#define _CU_SOFTMAC_API_H

/** @file cu_softmac_api.h
 * @brief The main SoftMAC header file.
 *
 * This file includes definitions for the functions, types, and constants
 * used by MAC and PHY layers in the SoftMAC system.
 */

/** \mainpage SoftMAC
 * 
 * \section intro_sec What is SoftMAC?
 *
 * SoftMAC is an abstraction designed to facilitate the creation
 * of custom and experimental MAC layers when used with Software
 * Defined Radio hardware. A traditional network interface system
 * is structured with a tightly coupled MAC and PHY layer exporting
 * a standard API to the operating system.
 *

  Network interface,
     e.g. eth0
       |
       |
 ++++++++++++++
+              +
+  OS Network  + 
+  Interface   +
+    Layer     +
+              +
 ++++++++++++++
       | 
 ++++++++++++++
+              +
+   MAC/PHY    +
+   software   +
+  driver and  +
+ network card + 
+  hardware    +
+              +    
 ++++++++++++++
       |
       |
 Network Medium

 *
 * This structure permits the easy swapping of underlying network
 * hardware. Two different brands of ethernet card will both show up
 * as eth0 on a system, and as long as the drivers and hardware
 * both function properly an application doesn't have to concern
 * itself with which network card is being used.
 *


 *
 * The SoftMAC breaks out the integrated MAC and PHY layer
 * into separate (but still coupled) components.
 *

  Network interface,
     e.g. eth0
       |
       |
 ++++++++++++++
+              +
+  OS Network  + 
+  Interface   +
+    Layer     +
+              +
 ++++++++++++++
       |
 ++++++++++++++
+              +
+ SoftMAC MAC  + 
+    Layer     +
+              +
 ++++++++++++++
       |
 ++++++++++++++
+              +
+ SoftMAC PHY  + 
+    Layer     +
+              +
 ++++++++++++++
       |
       |
 Network Medium

 * 
 * This structure affords even greater flexibility than the traditional
 * network stack when used with appropriately capable hardware. Most MAC
 * layers are still implemented either wholly or partially by the underlying
 * hardware and are immutable. With such hardware the SoftMAC abstraction
 * makes no sense, and serves only as an extra layer of inefficiency.
 * However, recent advances in <i>Software Defined Radio</i> technology
 * have resulted in much more flexible network hardware. Fully exploiting
 * the capabilities of this hardware requires a more flexible network
 * stack. SoftMAC is designed to strike a balance between flexibility
 * and efficiency that will permit experimentation with this hardware.
 *
 * \section sdr_sec Software Defined Radio
 *
 * A Software Defined Radio, or <i>SDR</i>, ...
 */


/*
**
**
** SoftMAC PHY Layer Functions
**
**
 */

/**
 * @brief Forward declaration of the structs containing layer information
 */
struct CU_SOFTMAC_LAYER_INFO_t;
struct CU_SOFTMAC_MACLAYER_INFO_t;
struct CU_SOFTMAC_PHYLAYER_INFO_t;

/**
 * @brief Maximum size of a MAC,PHY,LAYER name in SoftMAC
 */
#define CU_SOFTMAC_NAME_SIZE 64

/**
 * @brief Functions and variables exported by ALL layer classes
 */
typedef struct CU_SOFTMAC_LAYER_INFO_t {

    /**
     * @brief Layer name.  like "cheesymac" or "ath"
     */
    char name[CU_SOFTMAC_NAME_SIZE];
    
    /**
     * @brief Create a new instance of this layer type
     */
    void *(*cu_softmac_layer_new_instance)(void*);

    /**
     * @brief Destroy an existing instance of this layer type
     */
    void (*cu_softmac_layer_free_instance)(void*, void *inst);

    /**
     * @brief Private data
     */
    void *layer_private;

    /* softmac internal */
    struct hlist_node name_hlist;
} CU_SOFTMAC_LAYER_INFO;


/**
 * @brief Functions/variables exported by PHY layer.
 */
typedef struct CU_SOFTMAC_PHYLAYER_INFO_t {
    
    /**
     * @brief PHY layer instance name.  like "ath0"
     */
    char name[CU_SOFTMAC_NAME_SIZE];
    
    /** 
     * @brief Layer information
     */
    CU_SOFTMAC_LAYER_INFO *layer;

    /**
     * @brief Attach a MAC layer to the PHY layer
     */
    int (*cu_softmac_phy_attach_mac)(void *, struct CU_SOFTMAC_MACLAYER_INFO_t* macinfo);

    /**
     * @brief Detach a MAC layer from the PHY layer
     *
     * Tell the softmac PHY that we are leaving the building. The semantics
     * of this call are such that *after* it returns the SoftMAC PHY won't
     * make any new calls into the MAC layer.
     */
    void (*cu_softmac_phy_detach_mac)(void*, void* mypriv);
    /**
     * @brief Get current time
     *
     * This function is grouped with the PHY layer, even though it may
     * appear to be more of an OS-related function. However, some PHY layers
     * may have their own high-precision clocks that the MAC layer should
     * be using. For example, the Atheros PHY layer has such a clock.
     */
    u_int64_t (*cu_softmac_phy_get_time)(void*);

    /**
     * @brief Set current time
     */
    void (*cu_softmac_phy_set_time)(void*,u_int64_t time);

    /**
     * @brief Schedule the MAC layer <i>work</i> callback to be run
     * as soon as possible.
     */
    void (*cu_softmac_phy_schedule_work_asap)(void*);

    /**
     * @brief Allocate space for a packet.
     *
     * This function allocates an sk_buff with sufficient space to hold 
     * <i>datalen </i> bytes. This also includes sufficient headroom for whatever
     * additional headers the PHY layer may need to add as well as handling any
     * specia alignment or location requirements for efficient transfer to
     * hardware. For example, the Atheros PHY layer requires five extra bytes at
     * the beginning of each packet to ensure data integrity and
     * cacheline alignment to ensure speedy DMA transfers.
     */
    struct sk_buff* (*cu_softmac_phy_alloc_skb)(void*,int datalen);

    /**
     * @brief Free an sk_buff (packet) either allocated by a call to
     * CU_SOFTMAC_PHY_ALLOC_SKB_FUNC or passed in from the PHY layer.
     */
    void (*cu_softmac_phy_free_skb)(void*,struct sk_buff*);

    /**
     * @brief Send a packet, only permitting max_packets_inflight to be pending
     */
    int (*cu_softmac_phy_sendpacket)(void*,int max_packets_inflight,struct sk_buff* skb);

    /**
     * @brief Send a packet, only permitting max_packets_inflight to be pending,
     * do NOT free the sk_buff upon failure.
     *
     * This allows callers to do things
     * like requeue a packet if they care to make another attempt to send the
     * packet that failed to go out.
     */
    int (*cu_softmac_phy_sendpacket_keepskbonfail)(void*,int max_packets_inflight,struct sk_buff* skb);

    /**
     * @brief Ask the phy layer how long (in microseconds) it will take for this
     * packet to be transmitted, not including any initial transmit latency.
     */
    u_int32_t (*cu_softmac_phy_get_duration)(void*, struct sk_buff* skb);

    /**
     * @brief Ask the phy layer how much "lead time" there is between a request
     * to send a packet and the time it hits the air.
     */
    u_int32_t (*cu_softmac_phy_get_txlatency)(void*);

    /**
     * @brief PHY layer private data
     */
    void *phy_private;

    /* softmac internal */
    atomic_t refcnt;
    struct hlist_node name_hlist;

} CU_SOFTMAC_PHYLAYER_INFO;

/**
 * @brief Errors that might be returned from the send packet procedures
 */
enum {
    CU_SOFTMAC_PHY_SENDPACKET_OK = 0,
    CU_SOFTMAC_PHY_SENDPACKET_ERR_TOOMANYPENDING = -1000,
    CU_SOFTMAC_PHY_SENDPACKET_ERR_NETDOWN = -1001,
    CU_SOFTMAC_PHY_SENDPACKET_ERR_NOBUFFERS = -1002,
};


/*
**
**
** SoftMAC MAC Layer Functions
**
**
*/

typedef int (*CU_SOFTMAC_MAC_RX_FUNC)(void*,struct sk_buff* packet);
typedef void (*CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC)(void*);

/**
 * @brief Functions/data exported by a MAC layer implementation.
 */
typedef struct CU_SOFTMAC_MACLAYER_INFO_t {

    /**
     * @brief MAC layer instance name.  like "cheesy1"
     */
    char name[CU_SOFTMAC_NAME_SIZE];

    /** 
     * @brief Layer information
     */
    CU_SOFTMAC_LAYER_INFO *layer;

    /**
     * @brief Called when an ethernet-encapsulated packet is ready to transmit.
     */
    int (*cu_softmac_mac_packet_tx)(void*,struct sk_buff* thepacket,int intop);

    /**
     * @brief Called when transmission of a packet is complete.
     */
    int (*cu_softmac_mac_packet_tx_done)(void*,struct sk_buff* thepacket,int intop);

    /**
     * @brief Called upon receipt of a packet.
     */
    int (*cu_softmac_mac_packet_rx)(void*,struct sk_buff* thepacket,int intop);

    /**
     * @brief Notify the MAC layer that it is time to do some work.
     */
    int (*cu_softmac_mac_work)(void*,int intop);

    /**
     * @brief Notify the MAC layer that it is being removed from the PHY.
     */   
    int (*cu_softmac_mac_detach)(void*,int intop);

    /**
     * @brief Tell the MAC layer to attach to the specified PHY layer.
     */
    int (*cu_softmac_mac_attach_to_phy)(void*,CU_SOFTMAC_PHYLAYER_INFO*);

    /**
     * @brief Tell the MAC layer to detach from the specified PHY layer.
     */
    int (*cu_softmac_mac_detach_from_phy)(void*);

    /**
     * @brief
     */
    int (*cu_softmac_mac_set_rx_func)(void*,CU_SOFTMAC_MAC_RX_FUNC,void*);

    /**
     * @brief Notify the MAC layer that it is being removed from the PHY.
     */
    int (*cu_softmac_mac_set_unload_notify_func)(void*,CU_SOFTMAC_MAC_UNLOAD_NOTIFY_FUNC,void*);

    void* mac_private;

    /* softmac internal */
    atomic_t refcnt;
    struct hlist_node name_hlist;

} CU_SOFTMAC_MACLAYER_INFO;

/**
 * @brief Status codes returned by the MAC layer when receiving
 * a notification from the SoftMAC PHY
 */
enum {
    /**
     * @brief Finished running, all is well
     */
    CU_SOFTMAC_MAC_NOTIFY_OK = 0,
    /**
     * @brief Finished for now, but schedule task to run again ASAP
     */
    CU_SOFTMAC_MAC_NOTIFY_RUNAGAIN = 1,
    /**
     * @brief The MAC layer is busy and cannot take delivery of a packet.
     * The PHY layer should free the packet and continue.
     */
    CU_SOFTMAC_MAC_NOTIFY_BUSY = 2,
    /**
     * @brief The MAC layer is hosed. Free the packet and continue.
     */
    CU_SOFTMAC_MAC_NOTIFY_HOSED = 3,
};

enum {
    CU_SOFTMAC_MAC_TX_OK = 0,
    CU_SOFTMAC_MAC_TX_FAIL = -1,
};


/**
 **
 **
 ** SoftMAC Core Services 
 **
 **
 */

/**
 * @brief Create a new instance of a SoftMAC PHY or MAC layer
 * The 'cu_softmac_layer_new_instance' function corresponding to 'name' is called
 */
void *cu_softmac_layer_new_instance(const char *name);

/**
 * @brief Call the 'cu_softmac_layer_free_instance' function for the SoftMAC 
 * layer associatied with 'inst'
 */
void cu_softmac_layer_free_instance(void *inst);

/**
 * @brief Register a PHY or MAC layer with SoftMAC
 */
void cu_softmac_layer_register(CU_SOFTMAC_LAYER_INFO *info);

/**
 * @brief Remove a PHY or MAC layer from SoftMAC
 */
void cu_softmac_layer_unregister(CU_SOFTMAC_LAYER_INFO *info);

/**
 * @brief Register a MAC layer instance with SoftMAC
 */
void cu_softmac_macinfo_register(CU_SOFTMAC_MACLAYER_INFO* macinfo);

/**
 * @brief Remove a MAC layer instance from SoftMAC
 */
void cu_softmac_macinfo_unregister(CU_SOFTMAC_MACLAYER_INFO* macinfo);

/**
 * @brief Get a private copy of 'macinfo' (increment ref count)
 */
CU_SOFTMAC_MACLAYER_INFO* cu_softmac_macinfo_get(CU_SOFTMAC_MACLAYER_INFO* macinfo); 

/**
 * @brief Get a private copy of pointer to macinfo structure for 'name' (increment ref count)
 */
CU_SOFTMAC_MACLAYER_INFO* cu_softmac_macinfo_get_by_name(const char *name);

/**
 * @brief Allocate a macinfo structure representing a MAC layer instance (ref count = 1)
 */
CU_SOFTMAC_MACLAYER_INFO* cu_softmac_macinfo_alloc(void);

/**
 * @brief Dereference a pointer to a macinfo structure (decrement ref count), possibly deallocate
 */
void cu_softmac_macinfo_free(CU_SOFTMAC_MACLAYER_INFO* macinfo);

/**
 * @brief Initialize 'macinfo' to zero and set function pointers to "do nothing" functions
 */
void cu_softmac_macinfo_init(CU_SOFTMAC_MACLAYER_INFO* macinfo);

/**
 * @brief Register a PHY layer instance with SoftMAC
 */
void cu_softmac_phyinfo_register(CU_SOFTMAC_PHYLAYER_INFO* phyinfo);

/**
 * @brief Remove a PHY layer instance from SoftMAC
 */
void cu_softmac_phyinfo_unregister(CU_SOFTMAC_PHYLAYER_INFO* phyinfo);

/**
 * @brief Get a private copy of 'phyinfo' (increment ref count)
 */
CU_SOFTMAC_PHYLAYER_INFO* cu_softmac_phyinfo_get(CU_SOFTMAC_PHYLAYER_INFO* phyinfo);

/**
 * @brief Get a private copy of pointer to phyinfo structure for 'name'
 */
CU_SOFTMAC_PHYLAYER_INFO* cu_softmac_phyinfo_get_by_name(const char *name);

/**
 * @brief Allocate a phyinfo structure representing a PHY layer instance (ref count = 1)
 */
CU_SOFTMAC_PHYLAYER_INFO* cu_softmac_phyinfo_alloc(void);

/**
 * @brief Dereference a pointer to a phyinfo structure (decrement ref count), possibly deallocate
 */
void cu_softmac_phyinfo_free(CU_SOFTMAC_PHYLAYER_INFO* phyinfo); 

/**
 * @brief Initialize 'phyinfo' to zero and set function pointers to "do nothing" functions
 */
void cu_softmac_phyinfo_init(CU_SOFTMAC_PHYLAYER_INFO* phyinfo);



/* old stuff */

/*
 * We're also defining guidelines for "composable" MAC modules.
 * MAC modules that are "composable" need to export a couple of
 * key functions:
 *
 * 1) A "create_instance" function that takes a pointer to a "client_info"
 * structure and a CU_SOFTMAC_PHYLAYER_INFO and fills in appropriate values
 * for its notification functions and private data
 *
 * 2) A "set_cu_softmac_phylayer_info" function that sets the
 * CU_SOFTMAC_PHYLAYER_INFO that should be used by the MAC module
 * when accessing PHY layer softmac services.
 * 
 * In the initial iteration the "composite" MAC module will be assumed
 * to just "know" the names of these functions in the relevant MAC
 * layer modules and phy layers. Someone with more time/industry than
 * I've got right now could certainly make a "MAC broker" service that allowed
 * MAC layers to register and be referenced dynamically by some sort
 * of naming scheme by a composite MAC object.
 */

#endif
