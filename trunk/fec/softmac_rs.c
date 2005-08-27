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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/rslib.h>
#include "softmac_rs.h"
#include "rs.h"

MODULE_LICENSE("GPL");

/*
 *  SoftMAC RS helper module
 */

#define NAME "softmac_rs"
#define ENCBLKSZ 255     /* encoded block size */
#define BLKSZ    (255-32)  /* original data block size */

static struct rs_control *rsctl;

static int 
softmac_rs_encode_msg(char *dst, char *src, int len)
{
    while (len >= BLKSZ) {
	memcpy(dst, src, BLKSZ);
	encode_rs_8(dst, dst + BLKSZ, 0);
	len -= BLKSZ;
	src += BLKSZ;
	dst += ENCBLKSZ;
    }
    if (len) {
	memcpy(dst, src, len);
	encode_rs_8(dst, dst + len, BLKSZ-len);
    }
    return 1;
}

static int
softmac_rs_decode_msg(char *dst, char *src, int len)
{
  int errors = 0;

  while (len >= ENCBLKSZ) {
      errors += decode_rs_8(src, NULL, 0, 0);
      memcpy(dst, src, BLKSZ);
      len -= ENCBLKSZ;
      src += ENCBLKSZ;
      dst += BLKSZ;
  }
  if (len) {
      errors += decode_rs_8(src, NULL, 0, ENCBLKSZ-len);
      memcpy(dst, src, len-32);
  }
  return errors;
}

/* returns an encoded copy of the original skb. data
 * is encoded starting at skb->data+offset and the
 * the original skb is freed 
 */
struct sk_buff *
cu_softmac_rs_encode_skb(struct sk_buff *skb, int offset)
{
    struct sk_buff *skb2;
    int src_len, dst_len, d;
    char *src = skb->data + offset;

    src_len = skb->len - offset;
    dst_len = src_len / BLKSZ;
    dst_len = dst_len * ENCBLKSZ;
    if (src_len % BLKSZ)
	dst_len = dst_len + (src_len % BLKSZ) + 32;
    
    d = dst_len - src_len;
    skb2 = skb_copy_expand(skb, skb_headroom(skb), skb_tailroom(skb) + d, GFP_ATOMIC);

    softmac_rs_encode_msg(skb2->data+offset, src, src_len);
    skb_put(skb2, d);

    //printk(NAME ": rs_encode %d (%d) -> %d (%d)\n", src_len, skb->len, dst_len, skb2->len);

    kfree_skb(skb);
    return skb2;
}

/* returns the original skb, decoded and trimmed */
struct sk_buff *
cu_softmac_rs_decode_skb(struct sk_buff *skb, int* errorcount)
{
    int len, errs;

    errs = softmac_rs_decode_msg(skb->data, skb->data, skb->len);
    //if (errs)
    //printk(NAME ": errs = %d\n", errs);

    /* get rid of extra bytes */
    if (errorcount) *errorcount = errs;
    len = (skb->len / ENCBLKSZ) + 1; /* num blks */
    len *= (ENCBLKSZ - BLKSZ);       /* amt overhead */
    len = skb->len - len;            /* new len */

    //printk(NAME ": rs_decode %d -> ", skb->len);
    skb_trim(skb, len);
    //printk("%d\n", skb->len);

    return skb;
}

/* put some "random" errors in the packet starting at skb->data+offset */
void
cu_softmac_rs_make_errors(struct sk_buff *skb, int offset, int num_errors)
{
    int len, i;
    unsigned short errpos;
    char errval, *data;

    data = skb->data + offset;    
    len = skb->len - offset;

    for (i=0; i<num_errors; i++) {
	get_random_bytes(&errval, 1);
	get_random_bytes(&errpos, sizeof(errpos));
	errpos = errpos % len;
	data[errpos] = errval;
    }
}

static int __init softmac_rs_init(void)
{
    printk(NAME ": init\n");

    /* XXX init rs */
    //rsctl = init_rs(8,0x187,112,11,32);
    //if (!rsctl) printk("%s: error !rsctl\n", __func__);
    return 0;
}

static void __exit softmac_rs_exit(void)
{
    printk(NAME ": exit\n");
}

module_init(softmac_rs_init);
module_exit(softmac_rs_exit);

EXPORT_SYMBOL(cu_softmac_rs_encode_skb);
EXPORT_SYMBOL(cu_softmac_rs_decode_skb);
EXPORT_SYMBOL(cu_softmac_rs_make_errors);
