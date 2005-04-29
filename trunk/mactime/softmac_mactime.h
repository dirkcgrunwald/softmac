/*
 * softmac_mactime.h
 * SoftMAC functions for handling timed packet sending, e.g. TDMA
 */

/*
 * A client of the MACTime module is required to keep some state
 * around, i.e. the following structure, and hand it over to 
 * the MACTIME routine when making a request.
 */
typedef struct {
  CU_SOFTMAC_PHYLAYER_INFO* phyinfo;
  u_int32_t tdma_slotlen;
  u_int32_t tdma_slotcount;
  u_int32_t tdma_myslot;
  u_int32_t tdma_guardtime;
} CU_SOFTMAC_MACTIME_STATE;

/*
 * Indicates the current tdma slot status. Return values have following
 * semantics:
 *
 * >0 -> the time until the next slot arrives
 * <=0 -> -(time left in the current slot)
 */
int32_t cu_softmac_mactime_tdma_slotstatus(CU_SOFTMAC_MACTIME_STATE* mts,
					   u_int32_t* pcurslot);

int32_t cu_softmac_mactime_tdma_timetonextslot(CU_SOFTMAC_MACTIME_STATE* mts);
