
#define KTUND_SYNC 0x4B54554E /* "KTUN" */

struct ktund_packet_hdr {
    unsigned int    sync;     /* all packets start with KTUND_SYNC */
    unsigned short  ctl_len;  /* length of header, can be zero */
    unsigned short  data_len; /* length of data, can be zero */
};
