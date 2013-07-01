// This file was added by me to make applications compile - Atis


/* Various stub functions and uIP variables other code might need to
 * compile. Allows you to save needing to compile all of uIP in just
 * to get a few things */


#include "net/uip.h"
#include "net/uip-ds6.h"
#include <string.h>

#define UIP_IP_BUF   ((struct uip_ip_hdr *)&uip_buf[UIP_LLH_LEN])

uip_buf_t uip_aligned_buf;

uint16_t uip_len;

struct uip_stats uip_stat;

uip_lladdr_t uip_lladdr;

uint16_t uip_htons(uint16_t val) { return UIP_HTONS(val);}

uip_ds6_netif_t uip_ds6_if;

/********** UIP_DS6.c **********/

void
uip_ds6_set_addr_iid(uip_ipaddr_t *ipaddr, uip_lladdr_t *lladdr)
{
  /* We consider only links with IEEE EUI-64 identifier or
     IEEE 48-bit MAC addresses */
#if (UIP_LLADDR_LEN == 8)
  memcpy(ipaddr->u8 + 8, lladdr, UIP_LLADDR_LEN);
  ipaddr->u8[8] ^= 0x02;
#elif (UIP_LLADDR_LEN == 6)
  memcpy(ipaddr->u8 + 8, lladdr, 3);
  ipaddr->u8[11] = 0xff;
  ipaddr->u8[12] = 0xfe;
  memcpy(ipaddr->u8 + 13, lladdr + 3, 3);
  ipaddr->u8[8] ^= 0x02;
#else
#error fakeuip.c cannot build interface address when UIP_LLADDR_LEN is not 6 or 8
#endif
}

/*---------------------------------------------------------------------------*/
/*
 * get a link local address -
 * state = -1 => any address is ok. Otherwise state = desired state of addr.
 * (TENTATIVE, PREFERRED, DEPRECATED)
 */
uip_ds6_addr_t *
uip_ds6_get_link_local(int8_t state) {
  uip_ds6_addr_t *locaddr;
  for(locaddr = uip_ds6_if.addr_list;
      locaddr < uip_ds6_if.addr_list + UIP_DS6_ADDR_NB; locaddr++) {
    if((locaddr->isused) && (state == - 1 || locaddr->state == state)
       && (uip_is_addr_link_local(&locaddr->ipaddr))) {
      return locaddr;
    }
  }
  return NULL;
}

uip_ds6_addr_t *
uip_ds6_addr_add(uip_ipaddr_t *ipaddr, unsigned long vlifetime, uint8_t type)
{
  return NULL;
}
/********** UIP.c ****************/

static uint16_t
chksum(uint16_t sum, const uint8_t *data, uint16_t len)
{
  uint16_t t;
  const uint8_t *dataptr;
  const uint8_t *last_byte;

  dataptr = data;
  last_byte = data + len - 1;

  while(dataptr < last_byte) {   /* At least two more bytes */
    t = (dataptr[0] << 8) + dataptr[1];
    sum += t;
    if(sum < t) {
      sum++;      /* carry */
    }
    dataptr += 2;
  }

  if(dataptr == last_byte) {
    t = (dataptr[0] << 8) + 0;
    sum += t;
    if(sum < t) {
      sum++;      /* carry */
    }
  }

  /* Return sum in host byte order. */
  return sum;
}

static uint16_t
upper_layer_chksum(uint8_t proto)
{
  uint16_t upper_layer_len;
  uint16_t sum;

  upper_layer_len = (((uint16_t)(UIP_IP_BUF->len[0]) << 8) + UIP_IP_BUF->len[1]) ;

  /* First sum pseudoheader. */
  /* IP protocol and length fields. This addition cannot carry. */
  sum = upper_layer_len + proto;
  /* Sum IP source and destination addresses. */
  sum = chksum(sum, (uint8_t *)&UIP_IP_BUF->srcipaddr, 2 * sizeof(uip_ipaddr_t));

  /* Sum TCP header and data. */
  sum = chksum(sum, &uip_buf[UIP_IPH_LEN + UIP_LLH_LEN],
               upper_layer_len);

  return (sum == 0) ? 0xffff : uip_htons(sum);
}

/*---------------------------------------------------------------------------*/
uint16_t
uip_icmp6chksum(void)
{
  return upper_layer_chksum(UIP_PROTO_ICMP6);
}









#include "net/netstack.h"
#include "net/rime.h"
#include "net/rime/chameleon.h"
#include "net/rime/route.h"
#include "net/rime/announcement.h"
#include "net/rime/broadcast-announcement.h"
#include "net/mac/mac.h"

#include "lib/list.h"



static void
input(void)
{
  /* struct rime_sniffer *s; */
  /* struct channel *c; */

  /* RIMESTATS_ADD(rx); */
  /* c = chameleon_parse(); */
  
  /* for(s = list_head(sniffers); s != NULL; s = list_item_next(s)) { */
  /*   if(s->input_callback != NULL) { */
  /*     s->input_callback(); */
  /*   } */
  /* } */
  
  /* if(c != NULL) { */
  /*   abc_input(c); */
  /* } */
}
/*---------------------------------------------------------------------------*/
static void
init(void)
{
  /* queuebuf_init(); */
  /* packetbuf_clear(); */
  /* announcement_init(); */

  /* chameleon_init(); */
  
  /* /\* XXX This is initializes the transmission of announcements but it */
  /*  * is not currently certain where this initialization is supposed to */
  /*  * be. Also, the times are arbitrarily set for now. They should */
  /*  * either be configurable, or derived from some MAC layer property */
  /*  * (duty cycle, sleep time, or something similar). But this is OK */
  /*  * for now, and should at least get us started with experimenting */
  /*  * with announcements. */
  /*  *\/ */
  /* broadcast_announcement_init(BROADCAST_ANNOUNCEMENT_CHANNEL, */
  /*                             BROADCAST_ANNOUNCEMENT_BUMP_TIME, */
  /*                             BROADCAST_ANNOUNCEMENT_MIN_TIME, */
  /*                             BROADCAST_ANNOUNCEMENT_MAX_TIME); */
}
/*---------------------------------------------------------------------------*/
static void
packet_sent(void *ptr, int status, int num_tx)
{
  /* struct channel *c = ptr; */
  /* struct rime_sniffer *s; */
  
  /* switch(status) { */
  /* case MAC_TX_COLLISION: */
  /*   PRINTF("rime: collision after %d tx\n", num_tx); */
  /*   break;  */
  /* case MAC_TX_NOACK: */
  /*   PRINTF("rime: noack after %d tx\n", num_tx); */
  /*   break; */
  /* case MAC_TX_OK: */
  /*   PRINTF("rime: sent after %d tx\n", num_tx); */
  /*   break; */
  /* default: */
  /*   PRINTF("rime: error %d after %d tx\n", status, num_tx); */
  /* } */

  /* /\* Call sniffers, pass along the MAC status code. *\/ */
  /* for(s = list_head(sniffers); s != NULL; s = list_item_next(s)) { */
  /*   if(s->output_callback != NULL) { */
  /*     s->output_callback(status); */
  /*   } */
  /* } */

  /* abc_sent(c, status, num_tx); */
}
/*---------------------------------------------------------------------------*/
int
rime_output(struct channel *c)
{
  /* RIMESTATS_ADD(tx); */
  /* if(chameleon_create(c)) { */
  /*   packetbuf_compact(); */

  /*   NETSTACK_MAC.send(packet_sent, c); */
  /*   return 1; */
  /* } */
  return 0;
}
/*---------------------------------------------------------------------------*/
const struct network_driver rime_driver = {
  "Rime",
  init,
  input
};
/** @} */





#include "net/rime/rimeaddr.h"
#include <string.h>

rimeaddr_t rimeaddr_node_addr;
#if RIMEADDR_SIZE == 2
const rimeaddr_t rimeaddr_null = { { 0, 0 } };
#else /*RIMEADDR_SIZE == 2*/
#if RIMEADDR_SIZE == 8
const rimeaddr_t rimeaddr_null = { { 0, 0, 0, 0, 0, 0, 0, 0 } };
#endif /*RIMEADDR_SIZE == 8*/
#endif /*RIMEADDR_SIZE == 2*/


/*---------------------------------------------------------------------------*/
void
rimeaddr_copy(rimeaddr_t *dest, const rimeaddr_t *src)
{
	memcpy(dest, src, RIMEADDR_SIZE);
}
/*---------------------------------------------------------------------------*/
int
rimeaddr_cmp(const rimeaddr_t *addr1, const rimeaddr_t *addr2)
{
	return (memcmp(addr1, addr2, RIMEADDR_SIZE) == 0);
}
/*---------------------------------------------------------------------------*/
void
rimeaddr_set_node_addr(rimeaddr_t *t)
{
  rimeaddr_copy(&rimeaddr_node_addr, t);
}
/*---------------------------------------------------------------------------*/
/** @} */







#include <string.h>

#include "contiki-net.h"
#include "net/packetbuf.h"
#include "net/rime.h"

struct packetbuf_attr packetbuf_attrs[PACKETBUF_NUM_ATTRS];
struct packetbuf_addr packetbuf_addrs[PACKETBUF_NUM_ADDRS];


static uint16_t buflen, bufptr;
static uint8_t hdrptr;

/* The declarations below ensure that the packet buffer is aligned on
   an even 16-bit boundary. On some platforms (most notably the
   msp430), having apotentially misaligned packet buffer may lead to
   problems when accessing 16-bit values. */
static uint16_t packetbuf_aligned[(PACKETBUF_SIZE + PACKETBUF_HDR_SIZE) / 2 + 1];
static uint8_t *packetbuf = (uint8_t *)packetbuf_aligned;

static uint8_t *packetbufptr;

#define DEBUG 0
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

/*---------------------------------------------------------------------------*/
void
packetbuf_clear(void)
{
  buflen = bufptr = 0;
  hdrptr = PACKETBUF_HDR_SIZE;

  packetbufptr = &packetbuf[PACKETBUF_HDR_SIZE];
  packetbuf_attr_clear();
}
/*---------------------------------------------------------------------------*/
void
packetbuf_clear_hdr(void)
{
  hdrptr = PACKETBUF_HDR_SIZE;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_copyfrom(const void *from, uint16_t len)
{
  uint16_t l;

  packetbuf_clear();
  l = len > PACKETBUF_SIZE? PACKETBUF_SIZE: len;
  memcpy(packetbufptr, from, l);
  buflen = l;
  return l;
}
/*---------------------------------------------------------------------------*/
void
packetbuf_compact(void)
{
  int i, len;

  if(packetbuf_is_reference()) {
    memcpy(&packetbuf[PACKETBUF_HDR_SIZE], packetbuf_reference_ptr(),
	   packetbuf_datalen());
  } else if(bufptr > 0) {
    len = packetbuf_datalen() + PACKETBUF_HDR_SIZE;
    for(i = PACKETBUF_HDR_SIZE; i < len; i++) {
      packetbuf[i] = packetbuf[bufptr + i];
    }

    bufptr = 0;
  }
}
/*---------------------------------------------------------------------------*/
int
packetbuf_copyto_hdr(uint8_t *to)
{
#if DEBUG_LEVEL > 0
  {
    int i;
    PRINTF("packetbuf_write_hdr: header:\n");
    for(i = hdrptr; i < PACKETBUF_HDR_SIZE; ++i) {
      PRINTF("0x%02x, ", packetbuf[i]);
    }
    PRINTF("\n");
  }
#endif /* DEBUG_LEVEL */
  memcpy(to, packetbuf + hdrptr, PACKETBUF_HDR_SIZE - hdrptr);
  return PACKETBUF_HDR_SIZE - hdrptr;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_copyto(void *to)
{
#if DEBUG_LEVEL > 0
  {
    int i;
    char buffer[1000];
    char *bufferptr = buffer;
    
    bufferptr[0] = 0;
    for(i = hdrptr; i < PACKETBUF_HDR_SIZE; ++i) {
      bufferptr += sprintf(bufferptr, "0x%02x, ", packetbuf[i]);
    }
    PRINTF("packetbuf_write: header: %s\n", buffer);
    bufferptr = buffer;
    bufferptr[0] = 0;
    for(i = bufptr; i < buflen + bufptr; ++i) {
      bufferptr += sprintf(bufferptr, "0x%02x, ", packetbufptr[i]);
    }
    PRINTF("packetbuf_write: data: %s\n", buffer);
  }
#endif /* DEBUG_LEVEL */
  if(PACKETBUF_HDR_SIZE - hdrptr + buflen > PACKETBUF_SIZE) {
    /* Too large packet */
    return 0;
  }
  memcpy(to, packetbuf + hdrptr, PACKETBUF_HDR_SIZE - hdrptr);
  memcpy((uint8_t *)to + PACKETBUF_HDR_SIZE - hdrptr, packetbufptr + bufptr,
	 buflen);
  return PACKETBUF_HDR_SIZE - hdrptr + buflen;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_hdralloc(int size)
{
  if(hdrptr >= size && packetbuf_totlen() + size <= PACKETBUF_SIZE) {
    hdrptr -= size;
    return 1;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
void
packetbuf_hdr_remove(int size)
{
  hdrptr += size;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_hdrreduce(int size)
{
  if(buflen < size) {
    return 0;
  }

  bufptr += size;
  buflen -= size;
  return 1;
}
/*---------------------------------------------------------------------------*/
void
packetbuf_set_datalen(uint16_t len)
{
  PRINTF("packetbuf_set_len: len %d\n", len);
  buflen = len;
}
/*---------------------------------------------------------------------------*/
void *
packetbuf_dataptr(void)
{
  return (void *)(&packetbuf[bufptr + PACKETBUF_HDR_SIZE]);
}
/*---------------------------------------------------------------------------*/
void *
packetbuf_hdrptr(void)
{
  return (void *)(&packetbuf[hdrptr]);
}
/*---------------------------------------------------------------------------*/
void
packetbuf_reference(void *ptr, uint16_t len)
{
  packetbuf_clear();
  packetbufptr = ptr;
  buflen = len;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_is_reference(void)
{
  return packetbufptr != &packetbuf[PACKETBUF_HDR_SIZE];
}
/*---------------------------------------------------------------------------*/
void *
packetbuf_reference_ptr(void)
{
  return packetbufptr;
}
/*---------------------------------------------------------------------------*/
uint16_t
packetbuf_datalen(void)
{
  return buflen;
}
/*---------------------------------------------------------------------------*/
uint8_t
packetbuf_hdrlen(void)
{
  return PACKETBUF_HDR_SIZE - hdrptr;
}
/*---------------------------------------------------------------------------*/
uint16_t
packetbuf_totlen(void)
{
  return packetbuf_hdrlen() + packetbuf_datalen();
}
/*---------------------------------------------------------------------------*/
void
packetbuf_attr_clear(void)
{
  int i;
  for(i = 0; i < PACKETBUF_NUM_ATTRS; ++i) {
    packetbuf_attrs[i].val = 0;
  }
  for(i = 0; i < PACKETBUF_NUM_ADDRS; ++i) {
    rimeaddr_copy(&packetbuf_addrs[i].addr, &rimeaddr_null);
  }
}
/*---------------------------------------------------------------------------*/
void
packetbuf_attr_copyto(struct packetbuf_attr *attrs,
		    struct packetbuf_addr *addrs)
{
  memcpy(attrs, packetbuf_attrs, sizeof(packetbuf_attrs));
  memcpy(addrs, packetbuf_addrs, sizeof(packetbuf_addrs));
}
/*---------------------------------------------------------------------------*/
void
packetbuf_attr_copyfrom(struct packetbuf_attr *attrs,
		      struct packetbuf_addr *addrs)
{
  memcpy(packetbuf_attrs, attrs, sizeof(packetbuf_attrs));
  memcpy(packetbuf_addrs, addrs, sizeof(packetbuf_addrs));
}
/*---------------------------------------------------------------------------*/
#if !PACKETBUF_CONF_ATTRS_INLINE
int
packetbuf_set_attr(uint8_t type, const packetbuf_attr_t val)
{
/*   packetbuf_attrs[type].type = type; */
  packetbuf_attrs[type].val = val;
  return 1;
}
/*---------------------------------------------------------------------------*/
packetbuf_attr_t
packetbuf_attr(uint8_t type)
{
  return packetbuf_attrs[type].val;
}
/*---------------------------------------------------------------------------*/
int
packetbuf_set_addr(uint8_t type, const rimeaddr_t *addr)
{
/*   packetbuf_addrs[type - PACKETBUF_ADDR_FIRST].type = type; */
  rimeaddr_copy(&packetbuf_addrs[type - PACKETBUF_ADDR_FIRST].addr, addr);
  return 1;
}
/*---------------------------------------------------------------------------*/
const rimeaddr_t *
packetbuf_addr(uint8_t type)
{
  return &packetbuf_addrs[type - PACKETBUF_ADDR_FIRST].addr;
}
/*---------------------------------------------------------------------------*/
#endif /* PACKETBUF_CONF_ATTRS_INLINE */
/** @} */





void
queuebuf_to_packetbuf(struct queuebuf *b)
{
  /* struct queuebuf_ref *r; */
  /* if(memb_inmemb(&bufmem, b)) { */
  /*   struct queuebuf_data *buframptr = queuebuf_load_to_ram(b); */
  /*   packetbuf_copyfrom(buframptr->data, buframptr->len); */
  /*   packetbuf_attr_copyfrom(buframptr->attrs, buframptr->addrs); */
  /* } else if(memb_inmemb(&refbufmem, b)) { */
  /*   r = (struct queuebuf_ref *)b; */
  /*   packetbuf_clear(); */
  /*   packetbuf_copyfrom(r->ref, r->len); */
  /*   packetbuf_hdralloc(r->hdrlen); */
  /*   memcpy(packetbuf_hdrptr(), r->hdr, r->hdrlen); */
  /* } */
}
