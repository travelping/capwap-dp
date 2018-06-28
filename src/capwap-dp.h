/*
 * Copyright (C) 2014-2017, Travelping GmbH <info@travelping.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __CAPWAP_DP_H
#define __CAPWAP_DP_H

#include <net/ethernet.h>
#include <urcu/rcuhlist.h>      /* RCU hlist */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include "common.h"

/* global setting, cmdline arguments */

extern int v4only;
extern int v6only;
extern int capwap_port;
extern const char *capwap_ns;
extern const char *fwd_ns;
extern int honor_df;
extern int dhcp_relay;

extern int unknown_wtp_limit_interval;
extern int unknown_wtp_limit_bucket;

#define MAX_RADIOS 32
#define MAX_WLANS 16

#define MAX_FRAGMENTS 32
#define FRGMT_BUFFER (8 * 1024)
#define FRGMT_MAX 16

struct ratelimit {
	int interval;
	int bucket;
	int done;
	int missed;
	unsigned long begin;
};

struct frgmt {
	unsigned int fragment_id;

	unsigned int count;
	struct {
		unsigned int start;
		unsigned int end;
	} parts[FRGMT_MAX];

	unsigned int hdrlen;
	unsigned int length;

	unsigned char buffer[FRGMT_BUFFER];
};

struct frgmt_buffer {
	pthread_mutex_t lock;
	int base;
	struct frgmt frgmt[MAX_FRAGMENTS];
};

struct client;

struct station {
	struct rcu_head rcu_free;          /* For call_rcu() */
	struct rcu_head rcu_release;       /* For call_rcu() */
	struct urcu_ref ref;
	struct cds_lfht_node station_hash;
	struct cds_hlist_node wtp_list;

	struct client *wtp;
	uint8_t ether[ETH_ALEN];
	uint16_t vlan;
	unsigned int rid;
	uint8_t bssid[ETH_ALEN];

	unsigned long rcvd_pkts;
	unsigned long send_pkts;
	unsigned long rcvd_bytes;
	unsigned long send_bytes;
};

struct client {
	struct rcu_head rcu_head;       /* For call_rcu() */
	struct urcu_ref ref;
	struct cds_lfht_node node;

	struct sockaddr_storage addr;
	unsigned int mtu;
	uint16_t fragment_id;
	unsigned int sta_count;
	struct cds_hlist_head stations;
	struct cds_hlist_head wlans;
	struct frgmt_buffer frgmt_buffer;

	unsigned long rcvd_pkts;
	unsigned long send_pkts;
	unsigned long rcvd_bytes;
	unsigned long send_bytes;

	unsigned long rcvd_fragments;
	unsigned long send_fragments;

	unsigned long err_invalid_station;
	unsigned long err_fragment_invalid;
	unsigned long err_fragment_too_old;
};

struct wlan {
	struct rcu_head rcu_head;          /* For call_rcu() */
	struct urcu_ref ref;
	struct cds_hlist_node wlan_list;

	unsigned int rid;
	unsigned int wlan_id;

	uint8_t bssid[ETH_ALEN];
	uint16_t vlan;
};

struct worker {
	struct ev_loop *loop;
	pthread_mutex_t loop_lock; /* global loop lock */

	ev_io tap_ev;
	ev_io capwap_ev;
	ev_io dhcp_ev;
	ev_async stop_ev;

	unsigned int id;
	pthread_t tid;

	int tap_fd;
	int capwap_fd;
	int dhcp_fd;

	struct ratelimit unknown_wtp_limit;

	unsigned long rcvd_pkts;
	unsigned long send_pkts;
	unsigned long rcvd_bytes;
	unsigned long send_bytes;

	unsigned long rcvd_fragments;
	unsigned long send_fragments;

	unsigned long err_invalid_station;
	unsigned long err_fragment_invalid;
	unsigned long err_fragment_too_old;

	unsigned long err_invalid_wtp;
	unsigned long err_hdr_length_invalid;
	unsigned long err_too_short;
	unsigned long ratelimit_unknown_wtp;
};

extern int num_workers;
extern struct worker *workers;

extern struct cds_lfht *ht_stations;	/* Hash table */
extern struct cds_lfht *ht_clients;	/* Hash table */
extern char *tap_dev;

#define SIN_ADDR_PTR(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (void *)&(((struct sockaddr_in *)(addr))->sin_addr) : (void *)&(((struct sockaddr_in6 *)(addr))->sin6_addr))
#define SIN_PORT(addr) ((((struct sockaddr *)(addr))->sa_family == AF_INET) ? (((struct sockaddr_in *)(addr))->sin_port) : (((struct sockaddr_in6 *)(addr))->sin6_port))

void packet_in_tap(uint16_t vlan, const unsigned char *, ssize_t);
void capwap_in(const struct sockaddr *, const unsigned char *, unsigned int, const unsigned char *, ssize_t);
void dhcp_in(unsigned char *, ssize_t);

int start_worker(size_t);
unsigned long hash_sockaddr(const struct sockaddr *);

struct station *find_station(const uint8_t *);
struct client *find_wtp(const struct sockaddr *);

void attach_station_to_wtp(struct client *, struct station *);
void detach_station_from_wtp(struct station *);

struct client *add_wtp(const struct sockaddr *, unsigned int mtu);

void  __delete_wlan(struct wlan *wlan);
int __delete_station(struct station *sta);
int __delete_wtp(struct client *wtp);

void capwap_socket_error(int origin, int type, const struct sockaddr *addr);
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

#define CAPWAP_FRAG_ID_MASK     htobe32(0xFFFF0000)
#define CAPWAP_FRAG_ID_SHIFT    16
#define CAPWAP_FRAG_OFFS_MASK   htobe32(0x0000FFF8)
#define CAPWAP_FRAG_OFFS_SHIFT   3

enum capwap_payload_t {
	CAPWAP_802_3_PAYLOAD = 0,
	CAPWAP_802_11_PAYLOAD = 1
};

struct ieee80211_wbinfo{
	uint8_t length;
	uint16_t wlan_id_bitmap;
	uint16_t reserved;
} __attribute__ ((packed));


#endif // __CAPWAP_DP_H
