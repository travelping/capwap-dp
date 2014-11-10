#ifndef __CAPWAP_DP_H
#define __CAPWAP_DP_H

#include <net/ethernet.h>
#include <urcu/rcuhlist.h>      /* RCU hlist */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */

/* global setting, cmdline arguments */

extern int capwap_port;
extern const char *capwap_ns;
extern const char *fwd_ns;

struct client;

struct station {
        struct rcu_head rcu_head;       /* For call_rcu() */
	struct urcu_ref ref;
	struct cds_lfht_node station_hash;
	struct cds_hlist_node wtp_list;

	struct client *wtp;
	uint8_t ether[ETH_ALEN];
};

struct client {
        struct rcu_head rcu_head;       /* For call_rcu() */
	struct urcu_ref ref;
	struct cds_lfht_node node;

	struct sockaddr_storage addr;
	struct cds_hlist_head stations;
};

struct worker {
	struct ev_loop *loop;
	pthread_mutex_t loop_lock; /* global loop lock */

	ev_io tap_ev;
	ev_io capwap_ev;
	ev_async stop_ev;

	unsigned int id;
	pthread_t tid;

	int tap_fd;
	int capwap_fd;
};

extern struct worker *workers;

extern struct cds_lfht *ht_stations;	/* Hash table */
extern struct cds_lfht *ht_clients;	/* Hash table */

#define SIN_ADDR_PTR(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (void *)&(((struct sockaddr_in *)(addr))->sin_addr) : (void *)&(((struct sockaddr_in6 *)(addr))->sin6_addr))
#define SIN_PORT(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (((struct sockaddr_in *)(addr))->sin_port) : (((struct sockaddr_in6 *)(addr))->sin6_port))


int start_worker(size_t);
unsigned long hash_sockaddr(struct sockaddr *);

struct station *find_station(uint8_t *);
struct client *find_wtp(struct sockaddr *);

void attach_station_to_wtp(struct client *, struct station *);
void detach_station_from_wtp(struct station *);

/**
 * CAPWAP Transport Header
 *
 *        0                   1                   2                   3
 *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |CAPWAP Preamble|  HLEN   |   RID   | WBID    |T|F|L|W|M|K|Flags|
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |          Fragment ID          |     Frag Offset         |Rsvd |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                 (optional) Radio MAC Address                  |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |            (optional) Wireless Specific Information           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *       |                        Payload ....                           |
 *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#define GET_CAPWAP_HEADER_FIELD(hdr, mask, shift)		\
	((be32toh(*(uint32_t *)(hdr) & (mask))) >> (shift))

#define SET_CAPWAP_HEADER_FIELD(hdr, value, mask, shift)		\
	*(uint32_t *)(hdr) = (*(uint32_t *)(hdr) & ~(mask)) | htobe32((value) << (shift))

#define CAPWAP_HEADER_LEN    8

#define CAPWAP_PREAMBLE_MASK htobe32(0xFF000000)
#define CAPWAP_HLEN_SHIFT    19
#define CAPWAP_HLEN_MASK     htobe32(0x00F80000)
#define CAPWAP_RID_SHIFT     14
#define CAPWAP_RID_MASK      htobe32(0x0007C000)
#define CAPWAP_WBID_SHIFT     9
#define CAPWAP_WBID_MASK     htobe32(0x00003E00)
#define CAPWAP_F_MASK        htobe32(0x000001FF)

#define CAPWAP_F_TYPE        htobe32(0x00000100)
#define CAPWAP_F_TYPE_SHIFT   8
#define CAPWAP_F_FRAG        htobe32(0x00000080)
#define CAPWAP_F_LASTFRAG    htobe32(0x00000040)
#define CAPWAP_F_WSI         htobe32(0x00000020)
#define CAPWAP_F_RMAC        htobe32(0x00000010)
#define CAPWAP_F_K           htobe32(0x00000008)

#define CAPWAP_FRAG_ID_MASK     htobe32(xFFFF0000)
#define CAPWAP_FRAG_ID_SHIFT    16
#define CAPWAP_FRAG_OFFS_MASK   htobe32(x0000FFF8)
#define CAPWAP_FRAG_OFFS_SHIFT   3

enum capwap_payload_t {
	CAPWAP_802_3_PAYLOAD = 0,
	CAPWAP_802_11_PAYLOAD = 1
};

#endif // __CAPWAP_DP_H