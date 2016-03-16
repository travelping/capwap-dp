#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _REENTRANT

#include <assert.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/param.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/errqueue.h>

#include <ev.h>

#include <urcu.h>		/* RCU flavor */
#include <urcu/ref.h>		/* ref counting */
#include <urcu/rcuhlist.h>      /* RCU hlist */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */
#include "jhash.h"

#include "common.h"
#include "ieee802_11_defs.h"

#include "log.h"
#include "capwap-dp.h"
#include "netns.h"
#include "dhcp_internal.h"

int num_workers;
struct worker *workers;

struct cds_lfht *ht_stations;	/* Hash table */
struct cds_lfht *ht_clients;	/* Hash table */

static int capwap_ns_fd = 0;
static int fwd_ns_fd = 0;

static unsigned long get_ts()
{
	struct timespec monotime;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &monotime);

	return monotime.tv_sec * 1000 + monotime.tv_nsec / 10000000;
}

static int ratelimit(struct ratelimit *rs)
{
	unsigned long ts;

	if (!rs->interval)
		return 1;

	ts = get_ts();

	if (!rs->begin)
		rs->begin = ts;

	if (rs->begin + rs->interval < ts) {
		rs->begin = 0;
		rs->done = 0;
	}
	if (rs->bucket && rs->bucket > rs->done)
		goto doit;

	return 0;

doit:
	rs->done++;
	return 1;
}

static void rcu_free_client(struct rcu_head *head)
{
	struct client *clnt = caa_container_of(head, struct client, rcu_head);
	free(clnt);
}

static void ref_free_client(struct urcu_ref *ref)
{
	struct client *clnt = caa_container_of(ref, struct client, ref);
	call_rcu(&clnt->rcu_head, rcu_free_client);
}

static inline void refcount_get_client(struct client *clnt)
{
	urcu_ref_get(&clnt->ref);
}

static inline void refcount_put_client(struct client *clnt)
{
	urcu_ref_put(&clnt->ref, ref_free_client);
}

static void rcu_free_station(struct rcu_head *head)
{
	struct station *sta = caa_container_of(head, struct station, rcu_free);
	free(sta);
}

static void ref_free_station(struct urcu_ref *ref)
{
	struct station *sta = caa_container_of(ref, struct station, ref);
	call_rcu(&sta->rcu_free, rcu_free_station);
}

static inline void refcount_get_station(struct station *sta)
{
	urcu_ref_get(&sta->ref);
}

static inline void refcount_put_station(struct station *sta)
{
	urcu_ref_put(&sta->ref, ref_free_station);
}

void attach_station_to_wtp(struct client *wtp, struct station *sta)
{
	if (!sta || !wtp)
		return;

	/*
	 * need to bump refcounts on both structures:
	 *  - wtp refs sta through it's list
	 *  - sta refs wtp through it's wtp pointer element
	 */
	refcount_get_station(sta);
	refcount_get_client(wtp);

	sta->wtp = wtp;
	uatomic_inc(&wtp->sta_count);

	/*
	 * list mutating operations need mutal exclusion,
	 * this is currently guaranteed since only the
	 * control thread is permitted to call this
	 */
	cds_hlist_add_head_rcu(&sta->wtp_list, &wtp->stations);
}

static void rcu_release_wtp_from_sta(struct rcu_head *head)
{
	struct station *sta = caa_container_of(head, struct station, rcu_release);

	if (sta->wtp)
		refcount_put_client(sta->wtp);
	refcount_put_station(sta);
}

void detach_station_from_wtp(struct station *sta)
{
	if (!sta)
		return;

	uatomic_dec(&sta->wtp->sta_count);

	/*
	 * list mutating operations need mutal exclusion,
	 * this is currently guaranteed since only the
	 * control thread is permitted to call this
	 */
	cds_hlist_del_rcu(&sta->wtp_list);
	call_rcu(&sta->rcu_release, rcu_release_wtp_from_sta);
}

#define SOCK_ADDR_CMP(a, b, socktype, field)				\
	memcmp(&(((struct socktype *)(a))->field),			\
	       &(((struct socktype *)(b))->field),			\
	       sizeof(((struct socktype *)(a))->field))

#define SOCK_PORT_CMP(a, b, socktype, field)				\
	(((struct socktype *)(a))->field == ((struct socktype *)(b))->field)

static int match_ether(struct cds_lfht_node *ht_node, const void *_key)
{
	struct station *sta = caa_container_of(ht_node, struct station, station_hash);
	const uint8_t *key = _key;

	return memcmp(key, &sta->ether, ETH_ALEN) == 0;
}

static int match_sockaddr(struct cds_lfht_node *ht_node, const void *_key)
{
	struct client *client = caa_container_of(ht_node, struct client, node);
	const struct sockaddr *key = _key;

	if (client->addr.ss_family != key->sa_family)
		return 0;

	switch (key->sa_family) {
	case AF_INET:
		if (SOCK_ADDR_CMP(&client->addr, key, sockaddr_in, sin_addr) != 0)
			return 0;
		return SOCK_PORT_CMP(&client->addr, key, sockaddr_in, sin_port);

	case AF_INET6:
		if (SOCK_ADDR_CMP(&client->addr, key, sockaddr_in6, sin6_addr) != 0)
			return 0;
		return SOCK_PORT_CMP(&client->addr, key, sockaddr_in6, sin6_port);
	}

	return 0;
}

struct station *find_station(const uint8_t *ether)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;
	unsigned long hash;

	hash = jhash(ether, ETH_ALEN, 0x12345678);

	cds_lfht_lookup(ht_stations, hash, match_ether, ether, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node)
		return caa_container_of(ht_node, struct station, station_hash);

	return NULL;
}


static struct cds_lfht_node *get_wtp_node(const struct sockaddr *addr)
{
	struct cds_lfht_iter iter;
	unsigned long hash;
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

	hash = hash_sockaddr(addr);

#if defined(DEBUG)
	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	debug("IP: %s:%d, hash: 0x%08lx\n", ipaddr, ntohs(SIN_PORT(addr)), hash);
#endif

	cds_lfht_lookup(ht_clients, hash, match_sockaddr, addr, &iter);
	return cds_lfht_iter_get_node(&iter);
}

struct client *find_wtp(const struct sockaddr *addr)
{
	struct cds_lfht_node *ht_node;

	if ((ht_node = get_wtp_node(addr)) != NULL)
		return caa_container_of(ht_node, struct client, node);

	return NULL;
}

static void rcu_release_wtp(struct rcu_head *head)
{
	struct client *wtp = caa_container_of(head, struct client, rcu_head);

	refcount_put_client(wtp);
}

struct client *add_wtp(const struct sockaddr *addr, unsigned int mtu)
{
	struct client *wtp;
	unsigned long hash;
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

	hash = hash_sockaddr((struct sockaddr *)addr);

#if defined(DEBUG)
	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	debug("IP: %s:%d, hash: 0x%08lx\n", ipaddr, ntohs(SIN_PORT(addr)), hash);
#endif

	if (!(wtp = calloc(1, sizeof(struct client))))
	    return NULL;

	urcu_ref_init(&wtp->ref);
	cds_lfht_node_init(&wtp->node);
	CDS_INIT_HLIST_HEAD(&wtp->stations);
	pthread_mutex_init(&wtp->frgmt_buffer.lock, 0);
	memcpy(&wtp->addr, addr, sizeof(wtp->addr));
	wtp->mtu = mtu;

	/*
	 * cds_lfht_add() needs to be called from RCU read-side
	 * critical section.
	 */
	rcu_read_lock();

	/*
	 * Mutating operations need mutal exclusion from each other,
	 * only concurrent reads are allowed.
	 * This is currently guaranteed since only the
	 * control thread is permitted to call this.
	 */
	cds_lfht_add(ht_clients, hash, &wtp->node);

	rcu_read_unlock();

	return wtp;
}

int __delete_station(struct station *sta)
{
	int r;

	if ((r = cds_lfht_del(ht_stations, &sta->station_hash)) == 0) {
		detach_station_from_wtp(sta);
		refcount_put_station(sta);
	} else
		log(LOG_ALERT, "station hash corrupt");

	return r;
}

int __delete_wtp(struct client *wtp)
{
	int r;
	struct station *sta, *n;

	/*
	 * list and hash mutating operations need mutal exclusion,
	 * this is currently guaranteed since only the
	 * control thread is permitted to call this
	 */

	cds_hlist_for_each_entry_safe_2(sta, n, &wtp->stations, wtp_list)
		__delete_station(sta);

	if ((r = (cds_lfht_del(ht_clients, &wtp->node) == 0)))
		call_rcu(&wtp->rcu_head, rcu_release_wtp);

	return r;
}

static void stop_cb(EV_P_ ev_async *ev, int revents)
{
	struct worker *w = ev_userdata(EV_A);

	ev_io_stop(EV_A_ &w->capwap_ev);
	ev_async_stop(EV_A_ ev);

	close(w->capwap_ev.fd);

	ev_break(EV_A_ EVBREAK_ALL);
}

unsigned long hash_sockaddr(const struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return jhash(&((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr), ((struct sockaddr_in *)addr)->sin_port);


	case AF_INET6:
		return jhash(&((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr), ((struct sockaddr_in6 *)addr)->sin6_port);
	}

	return jhash(addr, sizeof(addr), 0);
}

static void forward_capwap(struct worker *w, struct client *wtp, const struct sockaddr *addr,
			   const unsigned char *radio_mac, unsigned int radio_mac_len,
			   struct ether_header *ether, unsigned char *data, unsigned int len)
{
	struct station *sta;
	struct iovec iov[2];
	int r __attribute__((unused));

	rcu_read_lock();

	debug("fwd CW ether: " PRIsMAC, ARGsMAC(ether->ether_shost));
	if ((sta = find_station(ether->ether_shost)) != NULL) {
		/* queue packet to TAP */

		debug("found STA %p, STA-WTP %p, WTP %p", sta, sta->wtp, wtp);

		uatomic_inc(&sta->rcvd_pkts);
		uatomic_add(&sta->rcvd_bytes, len + ETH_ALEN * 2);

		/* FIXME: shortcat write */
		iov[0].iov_base = ether;
		iov[0].iov_len = ETH_ALEN * 2;
		iov[1].iov_base = data;
		iov[1].iov_len = len;

		hexdump(iov[0].iov_base, iov[0].iov_len);
		hexdump(iov[1].iov_base, iov[1].iov_len);

		if ((r = writev(w->tap_fd, iov, 2)) < 0) {
			debug("writev: %m");
		}
		debug("fwd CW writev: %d", r);
	}
	else if (radio_mac_len == sizeof(ether->ether_shost) && memcmp(radio_mac, ether->ether_shost, radio_mac_len) == 0) {
		debug("got CAPWAP DP from RADIO MAC ("PRIsMAC"), ignoring", ARGsMAC(ether->ether_shost));
	} else {
		uatomic_inc(&w->err_invalid_station);
		uatomic_inc(&wtp->err_invalid_station);
		debug("got CAPWAP DP from unknown station " PRIsMAC, ARGsMAC(ether->ether_shost));
	}

	rcu_read_unlock();
}

static void handle_capwap_keep_alive(struct worker *w, struct client *wtp, struct msghdr *msg,
				     unsigned char *buffer, unsigned int len)
{
	const struct sockaddr *addr = (struct sockaddr *)msg->msg_name;

	if (wtp || (!wtp && ratelimit(&w->unknown_wtp_limit)))
		capwap_in(addr, NULL, 0, buffer, len);
	else
		uatomic_inc(&w->ratelimit_unknown_wtp);
}

static void handle_capwap_packet(struct worker *w, struct client *wtp, struct msghdr *msg, unsigned char *buffer, unsigned int len)
{
	const struct sockaddr *addr = (struct sockaddr *)msg->msg_name;
	unsigned int hlen    = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_HLEN_MASK, CAPWAP_HLEN_SHIFT) * 4;
	unsigned char *data  = buffer + hlen;
	unsigned int datalen = len - hlen;

	unsigned int wbid;
	unsigned int radio_mac_len = 0;
	unsigned char *radio_mac = NULL;

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_TYPE, 0))
		wbid = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_WBID_MASK, CAPWAP_WBID_SHIFT);
	else
		wbid = CAPWAP_802_3_PAYLOAD;

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_RMAC, 0)) {
		radio_mac_len = *(uint8_t *)(buffer + 8);
		radio_mac = (uint8_t *)(buffer + 9);
	}

	switch (wbid) {
	case CAPWAP_802_3_PAYLOAD:
		forward_capwap(w, wtp, addr, radio_mac, radio_mac_len, (struct ether_header *)data, data + ETH_ALEN * 2, datalen - ETH_ALEN * 2);
		break;

	case CAPWAP_802_11_PAYLOAD: {
		struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;
		struct ether_header *ether;
		uint16_t fc = le_to_host16(hdr->frame_control);

		debug("FrameType: %04x", fc);

		if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT) {
			/* push mgmt to controller */
			debug("management frame");
			capwap_in(addr, radio_mac, radio_mac_len, buffer, len);
			return;
		}
		else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA &&
			 (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) == WLAN_FC_FROMDS) {
			debug("addr1: " PRIsMAC, ARGsMAC(hdr->addr1));
			debug("addr2: " PRIsMAC, ARGsMAC(hdr->addr2));
			debug("addr3: " PRIsMAC, ARGsMAC(hdr->addr3));

			ether = (struct ether_header *)&hdr->addr1;
			memcpy(&ether->ether_shost, &hdr->addr3, ETH_ALEN);

			forward_capwap(w, wtp, addr, radio_mac, radio_mac_len, ether, data + sizeof(struct ieee80211_hdr), datalen - sizeof(struct ieee80211_hdr));
		} else {
			/* wrong direction / unknown / unhandled WLAN frame - ignore */
			debug("ignoring: type %d, To/From %d", WLAN_FC_GET_TYPE(fc), (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)));
			return;
		}
		break;
	}

	default:
		debug("ignoring: unsupported payload type %d", wbid);
		return;
	}
}

#define THDR_ROOM  64

#define in_range_s(v, start, end)		\
	(((v) >= (start)) && ((v) < (end)))
#define in_range_e(v, start, end)		\
	(((v) > (start)) && ((v) <= (end)))

#define overlap(s1, e1, s2, e2)					\
	(in_range_s(s1, s2, e2) || in_range_e(e1, s2, e2) ||	\
	 in_range_s(s2, s1, e1) || in_range_e(e2, s1, e1))

#if defined(DEBUG)

static void debug_fragments(struct frgmt *f, const char *tag)
{
	struct timeval tv;
	int i;

	gettimeofday(&tv, NULL);

	for (i = 0; i < f->count; i++) {
		debug_head(&tv);
		debug_log("   %s:[%2d]: %8d/%8d\n", tag, i, f->parts[i].start, f->parts[i].end);
	}
	debug_flush();
}

#else

#define debug_fragments(f, tag) do {} while (0)

#endif


static int add_fragment(struct frgmt *f, unsigned char *buffer, unsigned int len)
{
	unsigned int hlen = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_HLEN_MASK, CAPWAP_HLEN_SHIFT) * 4;
	unsigned char *data = buffer + hlen;
	unsigned int datalen = len - hlen;

	unsigned int start = GET_CAPWAP_HEADER_FIELD(buffer + 4, CAPWAP_FRAG_OFFS_MASK, CAPWAP_FRAG_OFFS_SHIFT) * 8;
	unsigned int end = start + datalen;
	int last = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_LASTFRAG, 0);

	int i;

	debug("add_fragment: new start: %d, end: %d", start, end);
	debug_fragments(f, "before");

	for (i = 0; i < f->count; i++) {
		if (overlap(f->parts[i].start, f->parts[i].end, start, end)) {
			debug("Action: skip due to overlap");
			return 0;
		}

		if (f->parts[i].end == start) {
			/* append to current fragment */
			debug("Action: append to current fragment");
			f->parts[i].end = end;

			if (i + 1 < f->count)
				if (f->parts[i].end == f->parts[i + 1].start) {
					/* merge current to next fragment */
					debug("Action: merge current to next fragment");
					f->parts[i].end = f->parts[i + 1].end;
					f->count--;

					if (i + 1 < f->count)
						memmove(&f->parts[i + 1], &f->parts[i + 2], sizeof(f->parts[i]) * (f->count - (i + 2)));
				}
			break;
		}
		else if (f->parts[i].start == end) {
			/* prepend to current fragment */
			debug("Action: prepend to current fragment");
			f->parts[i].start = start;

			break;
		}
		else if (f->parts[i].start > start) {
			/* insert before */
			debug("Action: insert before current fragment");
			if (f->count >= FRGMT_MAX)
				return 0;

			memmove(&f->parts[i + 1], &f->parts[i], sizeof(f->parts[i]) * (f->count - i));
			f->parts[i].start = start;
			f->parts[i].end = end;
			f->count++;

			break;
		}
	}
	if (i == f->count) {
		debug("Action: append to list");
		if (f->count >= FRGMT_MAX)
			return 0;

		f->parts[i].start = start;
		f->parts[i].end = end;
		f->count++;
	}

	debug_fragments(f, "after");

	if (last)
		f->length = end;

	if (start == 0) {
		if (hlen > THDR_ROOM)
			/* make sure the transport header fits the reserved space */
			return 0;

		/* first packet - take everything, including the transport header */
		f->hdrlen = hlen;
		memcpy(f->buffer + THDR_ROOM - f->hdrlen, buffer, len);
	} else
		/* fragment - only take the payload */
		memcpy(f->buffer + THDR_ROOM + start, data, datalen);

	/* - have seen the first and the last packet,
	 * - only one (whole) part remains and i covers the full payload */
	return (f->length != 0 && f->hdrlen != 0) &&
		(f->count == 1 && f->parts[0].start == 0 && f->parts[0].end == f->length);
}

static void handle_capwap_fragment(struct worker *w, struct client *wtp, struct msghdr *msg, unsigned char *buffer, unsigned int len)
{
	unsigned int hlen = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_HLEN_MASK, CAPWAP_HLEN_SHIFT) * 4;
	unsigned int datalen = len - hlen;

	unsigned int id, fragment_id = id = GET_CAPWAP_HEADER_FIELD(buffer + 4, CAPWAP_FRAG_ID_MASK, CAPWAP_FRAG_ID_SHIFT);
	unsigned int start = GET_CAPWAP_HEADER_FIELD(buffer + 4, CAPWAP_FRAG_OFFS_MASK, CAPWAP_FRAG_OFFS_SHIFT) * 8;
	unsigned int end = start + datalen;
	int last = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_LASTFRAG, 0);

	struct frgmt *f;
	int done;

	debug("Fragment Id: %d, offset: %d, end: %d, last: %d", fragment_id, start, end, !!last);

	if ((!last && (datalen % 8) != 0) || end > FRGMT_BUFFER) {
		debug("invalid fragment, size %d, end %d", datalen, end);
		uatomic_inc(&w->err_fragment_invalid);
		uatomic_inc(&wtp->err_fragment_invalid);
		return;
	}

	if (start == 0) {
		uatomic_inc(&w->rcvd_fragments);
		uatomic_inc(&wtp->rcvd_fragments);
	}

	pthread_mutex_lock(&wtp->frgmt_buffer.lock);

	if (wtp->frgmt_buffer.base > 0x8000 && id < (wtp->frgmt_buffer.base - 0x8000))
		/* 16bit wrap */
		id += 0x10000;

	debug("Fragment buffer: base: %d, Id: %d", wtp->frgmt_buffer.base, id);

	if (id < wtp->frgmt_buffer.base) {
		/* fragment to old */
		debug("Fragment too old");
		uatomic_inc(&w->err_fragment_too_old);
		uatomic_inc(&wtp->err_fragment_too_old);
		return;
	}

	if (id - wtp->frgmt_buffer.base > MAX_FRAGMENTS)
		wtp->frgmt_buffer.base = id - MAX_FRAGMENTS;

	f = &wtp->frgmt_buffer.frgmt[id % MAX_FRAGMENTS];
	if (f->fragment_id != fragment_id) {
		memset(f, 0, sizeof(*f));
		f->fragment_id = fragment_id;
	}

	done = add_fragment(f, buffer, len);
	if (done) {
		handle_capwap_packet(w, wtp, msg, f->buffer + THDR_ROOM - f->hdrlen, f->hdrlen + f->length);
		if (wtp->frgmt_buffer.base == f->fragment_id)
			/* advance base fragment id */
			wtp->frgmt_buffer.base++;
	}

	pthread_mutex_unlock(&wtp->frgmt_buffer.lock);
}

#undef THDR_ROOM
#undef in_range_s
#undef in_range_e
#undef overlap

static void capwap_recv(struct worker *w, struct msghdr *msg, unsigned char *buffer, unsigned int len)
{
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));
	const struct sockaddr *addr = (struct sockaddr *)msg->msg_name;
	struct client *wtp;

	unsigned int hlen;

#if defined(DEBUG)
	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	debug("read %d bytes from %s:%d",
	      len, ipaddr, ntohs(SIN_PORT(addr)));
	hexdump(buffer, len);
#endif

	rcu_read_lock();
	wtp = find_wtp(addr);

	uatomic_inc(&w->rcvd_pkts);
	uatomic_add(&w->rcvd_bytes, len);

	if (len < CAPWAP_HEADER_LEN) {
		debug("capwap packet shorter than header");
		uatomic_inc(&w->err_hdr_length_invalid);
		goto out_unlock;
	}

	hlen = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_HLEN_MASK, CAPWAP_HLEN_SHIFT) * 4;
	if (len < hlen) {
		debug("capwap packet shorter than length in header");
		uatomic_inc(&w->err_too_short);
		goto out_unlock;
	}

	wtp = find_wtp(addr);
	if (wtp) {
		uatomic_inc(&wtp->rcvd_pkts);
		uatomic_add(&wtp->rcvd_bytes, len);
	}

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_K, 0)) {
		debug("capwap keep-alive packet");
		handle_capwap_keep_alive(w, wtp, msg, buffer, len);
		goto out_unlock;
	}

	/* non keep-alives from unknown WTP's are not permitted */
	if (!wtp) {
		uatomic_inc(&w->err_invalid_wtp);
		goto out_unlock;
	}

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_FRAG, 0))
		handle_capwap_fragment(w, wtp, msg, buffer, len);
	else
		handle_capwap_packet(w, wtp, msg, buffer, len);

out_unlock:
	rcu_read_unlock();
}

static void wtp_update_mtu(struct sockaddr *addr, int mtu)
{
	struct client *wtp;

	rcu_read_lock();

	wtp = find_wtp(addr);
	debug("Update MTU for WTP %p to %d", wtp, mtu);
	if (wtp && uatomic_read(&wtp->mtu) > mtu)
		uatomic_set(&wtp->mtu, mtu);

	rcu_read_unlock();
}

static void handle_icmp_error(struct sock_extended_err *sock_err,
			      struct sockaddr *remote)
{
	struct sockaddr *addr = SO_EE_OFFENDER(sock_err);
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

#if defined(DEBUG)
	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	debug("ICMP Offender IP: %s:%d", ipaddr, ntohs(SIN_PORT(addr)));

	inet_ntop(remote->sa_family, SIN_ADDR_PTR(remote), ipaddr, sizeof(ipaddr));
	debug("ICMP Origin IP: %s:%d", ipaddr, ntohs(SIN_PORT(remote)));
#endif

	/* Handle ICMP errors types */
	switch (sock_err->ee_type) {
	case ICMP_DEST_UNREACH:
		switch (sock_err->ee_code) {
		case ICMP_NET_UNREACH:
			/* Network Unreachable          */
			debug("Network Unreachable Error");
			break;

		case ICMP_HOST_UNREACH:
			/* Host Unreachable             */
			debug("Host Unreachable Error");
			break;

		case ICMP_PORT_UNREACH:
			/* Port Unreachable             */
			debug("Port Unreachable Error");
			break;

		case ICMP_FRAG_NEEDED:
			/* Fragmentation Needed/DF set  */
			wtp_update_mtu(remote, sock_err->ee_info);
			break;

		default:
			/* Handle all other cases. Find more errors :
			 * http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
			 */
			debug("got Destination Unreachable, Code %d", sock_err->ee_code);
			break;
		}
		break;

	default:
		/* Handle all other cases. Find more errors :
		 * http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
		 */
		debug("got ICMP Error %d", sock_err->ee_type);
		break;
	}
}

static void capwap_read_error_q(struct worker *w, int fd)
{
	ssize_t r;
	char ctrl[1024];
	struct iovec iov;                       /* Data array */
	struct msghdr msg;                      /* Message header */
	struct cmsghdr *cmsg;                   /* Control related data */
	struct sock_extended_err *sock_err;     /* Struct describing the error */
	char data[2048];                        /* ICMP Data */
	struct sockaddr_storage remote;         /* Our socket */
	char ipaddr[INET6_ADDRSTRLEN] __attribute__((unused));

	for (;;) {
		memset(data, 0, sizeof(data));
		memset(&remote, 0, sizeof(remote));
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = data;
		iov.iov_len = sizeof(data);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_name = (void*)&remote;
		msg.msg_namelen = sizeof(remote);
		msg.msg_flags = 0;
		msg.msg_control = ctrl;
		msg.msg_controllen = sizeof(ctrl);

		/* Receiving errors flog is set */
		if ((r = recvmsg(fd, &msg, MSG_ERRQUEUE)) < 0)
			break;

#if defined(DEBUG)
		debug("Msg Flags: %08x", msg.msg_flags);
		inet_ntop(remote.ss_family, SIN_ADDR_PTR(&remote), ipaddr, sizeof(ipaddr));
		debug("Remote IP: %s:%d", ipaddr, ntohs(SIN_PORT(&remote)));

		hexdump(msg.msg_name, msg.msg_namelen);
#endif

		/* Control messages are always accessed via some macros
		 * http://www.kernel.org/doc/man-pages/online/pages/man3/cmsg.3.html
		 */
		for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))  {
			debug("CMSG: Level: %d, Type: %d", cmsg->cmsg_level, cmsg->cmsg_type);
			/* Ip level */
			if (cmsg->cmsg_level == SOL_IP &&
			    cmsg->cmsg_type == IP_RECVERR) {
				debug("We got IP_RECVERR message (msg_name: %p)", msg.msg_name);
				sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);

/*
				if (sock_err) capwap_socket_error(sock_err->ee_origin,
								  sock_err->ee_type,
								  msg.msg_name);
*/
				if (sock_err)
					debug("IP_RECVERR: origin: %d, type: %d",
					      sock_err->ee_origin, sock_err->ee_type);

				if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP)
					handle_icmp_error(sock_err, (struct sockaddr *)&remote);
			}
			else if (cmsg->cmsg_level == SOL_IPV6 &&
				 cmsg->cmsg_type == IPV6_RECVERR) {
				debug("We got IPV6_RECVERR message (msg_name: %p)", msg.msg_name);
				sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);

				if (sock_err) {
					debug("IPV6_RECVERR: origin: %d, type: %d",
					      sock_err->ee_origin, sock_err->ee_type);
					switch (sock_err->ee_origin) {
					case SO_EE_ORIGIN_LOCAL:
						debug("LOCAL info: %d", sock_err->ee_info);
						break;

					case SO_EE_ORIGIN_ICMP:
						handle_icmp_error(sock_err, (struct sockaddr *)&remote);
						break;

					case SO_EE_ORIGIN_ICMP6:
						/* TODO */
						break;

					}
				}
			}
		}
	}
}

static void capwap_cb(EV_P_ ev_io *ev, int revents)
{
	int i;
	ssize_t r;
#define VLEN 16
#define BUFSIZE 2048

	struct mmsghdr msgs[VLEN];
	struct sockaddr_storage addrs[VLEN];
	struct iovec iovecs[VLEN];
	unsigned char bufs[VLEN][BUFSIZE];

	struct worker *w = ev_userdata (EV_A);

	debug("read (%x) from %d", revents, ev->fd);

	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < VLEN; i++) {
		msgs[i].msg_hdr.msg_name    = &addrs[i];
		msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
		iovecs[i].iov_base          = bufs[i];
		iovecs[i].iov_len           = BUFSIZE;
		msgs[i].msg_hdr.msg_iov     = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen  = 1;
	}

	r = recvmmsg(ev->fd, msgs, VLEN, MSG_DONTWAIT, NULL);
	if (r < 0) {
		if (errno == EAGAIN)
			capwap_read_error_q(w, ev->fd);
		else
			debug("recvmmsg: %m");
		return;
	}

	debug("%zd CAPWAP messages received", r);
	for (i = 0; i < r; i++) {
		debug("flags: %d", msgs[i].msg_hdr.msg_flags);
		capwap_recv(w, &msgs[i].msg_hdr, bufs[i], msgs[i].msg_len);
	}

#undef VLEN
#undef BUFSIZE
}

static int df_bit(const unsigned char *buffer, ssize_t len)
{
	struct ether_header *ether = (struct ether_header *)buffer;

	switch (ntohs(ether->ether_type)) {
	case ETHERTYPE_IP: {
		ssize_t plen = len - sizeof(struct ether_header);
		struct ip *ip = (struct ip *)(ether + 1);

		if (plen < sizeof(struct ip))
			return 0;

		return !!(ntohs(ip->ip_off) & IP_DF);
	}
	case ETHERTYPE_IPV6:
		return 1;
	}
	return 0;
}

/*
 *      This table is the definition of how we handle ICMP.
 */
static const unsigned char icmp_pointers[] = {
	[ICMP_ECHOREPLY] = 0,
	[1] = 1,
	[2] = 1,
	[ICMP_DEST_UNREACH] = 1,
	[ICMP_SOURCE_QUENCH] = 1,
	[ICMP_REDIRECT] = 1,
	[6] = 1,
	[7] = 1,
	[ICMP_ECHO] = 0,
	[9] = 1,
	[10] = 1,
	[ICMP_TIME_EXCEEDED] = 1,
	[ICMP_PARAMETERPROB] = 1,
	[ICMP_TIMESTAMP] = 0,
	[ICMP_TIMESTAMPREPLY] = 0,
	[ICMP_INFO_REQUEST] = 0,
	[ICMP_INFO_REPLY] = 0,
	[ICMP_ADDRESS] = 0,
	[ICMP_ADDRESSREPLY] = 0
};

static uint32_t cksum_part(uint8_t *ip, int len, uint32_t sum)
{
	while (len > 1) {
		sum += *(uint16_t *)ip;
		if (sum & 0x80000000)   /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
		ip += 2;
	}

	if (len)       /* take care of left over byte */
		sum += (uint16_t) *(uint8_t *)ip;

	return sum;
}

static uint16_t cksum_finish(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

static uint16_t cksum(uint8_t *ip, int len)
{
	return cksum_finish(cksum_part(ip, len, 0));
}

static int send_icmp_pkt_to_big(struct worker *w, unsigned int mtu, const unsigned char *buffer, ssize_t len)
{
	struct ether_header *ether_in = (struct ether_header *)buffer;
	struct ether_header *ether_out;
	struct iovec iov[2];
	unsigned int room;
	unsigned char b[128];
	int r __attribute__((unused));

	/* No replies to physical multicast/broadcast */
	debug("ether_dhost: 0x%02x, %d", ether_in->ether_dhost[0], ether_in->ether_dhost[0] & 0x01);
	if (ether_in->ether_dhost[0] & 0x01)
		return 1;

	memset(&b, 0, sizeof(b));

	iov[0].iov_base = &b;
	/* skip the ether header */
	iov[1].iov_base = (unsigned char *)buffer + sizeof(struct ether_header);

	ether_out = (struct ether_header *)&b;
	memcpy(ether_out->ether_dhost, ether_in->ether_shost, sizeof(ether_out->ether_dhost));
	memcpy(ether_out->ether_shost, ether_in->ether_dhost, sizeof(ether_out->ether_shost));
	ether_out->ether_type = ether_in->ether_type;

	debug("ether_type: %d", ntohs(ether_in->ether_type));

	switch (ntohs(ether_in->ether_type)) {
	case ETHERTYPE_IP: {
		struct iphdr *ip_in = (struct iphdr *)(ether_in + 1);
		struct iphdr *iph = (struct iphdr *)(ether_out + 1);

		/* Only reply to fragment 0. */
		if (ip_in->frag_off & htons(0x1FFF))
			return 1;

		/* If we send an ICMP error to an ICMP error a mess would result.. */
		if (ip_in->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmph = (struct icmphdr *)(buffer + sizeof(struct ether_header) + ip_in->ihl * 4);

			/* Assume any unknown ICMP type is an error. */
			if (icmph->type > CAA_ARRAY_SIZE(icmp_pointers) || icmp_pointers[icmph->type])
				return 1;
		}

		iov[0].iov_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
		iov[1].iov_len = len - sizeof(struct ether_header);

		/* RFC says return as much as we can without exceeding 576 bytes. */
		room = 576 - sizeof(struct iphdr) + sizeof(struct icmphdr);
		if (iov[1].iov_len > room)
			iov[1].iov_len = room;


		iph->version = 4;
		iph->ihl = sizeof(struct iphdr) / 4;
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + iov[1].iov_len);
		iph->ttl = 64;
		iph->tos = (ip_in->tos & IPTOS_TOS_MASK) | IPTOS_PREC_INTERNETCONTROL;
		iph->protocol = IPPROTO_ICMP;
		iph->saddr = ip_in->daddr;               /* FIXME: this should be OUR address */
		iph->daddr = ip_in->saddr;
		iph->check = cksum((uint8_t *)iph, sizeof(struct iphdr));

		/*
		 * we don't do IP options
		 */

		struct icmphdr *icmp = (struct icmphdr *)(iph + 1);

		icmp->type        = ICMP_DEST_UNREACH;
		icmp->code        = ICMP_FRAG_NEEDED;
		icmp->un.frag.mtu = htons(mtu);

		uint32_t csum;
		csum = cksum_part((uint8_t *)icmp, sizeof(struct icmphdr), 0);
		csum = cksum_part((uint8_t *)iov[1].iov_base, iov[1].iov_len, csum);
		icmp->checksum = cksum_finish(csum);

		/* send! */
		if ((r = writev(w->tap_fd, iov, 2)) < 0) {
			debug("writev: %m");
		}
		debug("send icmp writev: %d", r);
	}
	break;

	case ETHERTYPE_IPV6:
		/* TODO !!! */
		break;

	default:
		return 1;
	}


	return 1;
}

static int ieee8023_to_wtp(struct worker *w, struct client *wtp, const unsigned char *buffer, ssize_t len)
{
	ssize_t r __attribute__((unused));
	struct iovec iov[2];
	struct msghdr mh;

	ssize_t hlen;
	unsigned char chdr[32];

	unsigned int mtu;
	int is_frag = 0;
	unsigned int frag_id = 0;
	unsigned int frag_count = 1;
	ssize_t max_len;
	ssize_t frag_size = len;

	/* TODO: calculate hlen based on binding and optional header */
	hlen = 2;
	mtu = uatomic_read(&wtp->mtu);

	max_len = mtu - sizeof(struct iphdr) - sizeof(struct udphdr) - hlen * 4;

	if (len > max_len) {
		frag_size = ((mtu - sizeof(struct iphdr) - sizeof(struct udphdr) - hlen * 4) / 8) * 8;
		frag_count = (len + frag_size - 1) / frag_size;
		is_frag = 1;
	}

	debug("Aligned MSS: %zd", frag_size);
	debug("Fragments #: %d", frag_count);
	debug("is_frag:     %d", is_frag);
	debug("df_bit:      %d", df_bit(buffer, len));

	if (honor_df && is_frag && df_bit(buffer, len))
		return send_icmp_pkt_to_big(w, max_len - sizeof(struct ether_header), buffer, len);

	if (is_frag && !frag_id)
		frag_id = uatomic_add_return(&wtp->fragment_id, 1);

	debug("frag_id: %d", frag_id);

	memset(chdr, 0, sizeof(chdr));

	/* Version = 0, Type = 0, HLen = 8, RId = 1, WBID 802.11, 802.3 encoding */
	((uint32_t *)chdr)[0] = htobe32((hlen << CAPWAP_HLEN_SHIFT) |
					(1 << CAPWAP_RID_SHIFT) |
					(CAPWAP_802_11_PAYLOAD << CAPWAP_WBID_SHIFT));
	if (is_frag) {
		((uint32_t *)chdr)[0] |= CAPWAP_F_FRAG;
		uatomic_inc(&w->send_fragments);
		uatomic_inc(&wtp->send_fragments);
	}
	((uint32_t *)chdr)[1] = htobe32(frag_id << CAPWAP_FRAG_ID_SHIFT);

	/* no RADIO MAC */
	/* no WSI */

	/* The message header contains parameters for sendmsg.    */
	memset(&mh, 0, sizeof(mh));
	mh.msg_name = (caddr_t)&wtp->addr;
	mh.msg_namelen = sizeof(wtp->addr);
	mh.msg_iov = iov;
	mh.msg_iovlen = 2;

	iov[0].iov_base = chdr;
	iov[0].iov_len = hlen * 4;

	iov[1].iov_base = (unsigned char *)buffer;
	iov[1].iov_len = frag_size;

	ssize_t offs = 0;

	for (; frag_count > 0; frag_count--) {
		debug("Id: %d, Count: %d", frag_id, frag_count);
		if (caa_unlikely(is_frag)) {
			SET_CAPWAP_HEADER_FIELD(&((uint32_t *)chdr)[1], offs / 8, CAPWAP_FRAG_OFFS_MASK, CAPWAP_FRAG_OFFS_SHIFT);
			if (frag_count == 1) {
				((uint32_t *)chdr)[0] |= CAPWAP_F_LASTFRAG;
				iov[1].iov_len = len % frag_size;
			}
		}

		uatomic_inc(&w->send_pkts);
		uatomic_inc(&wtp->send_pkts);
		uatomic_add(&w->send_bytes, iov[0].iov_len + iov[1].iov_len);
		uatomic_add(&wtp->send_bytes, iov[0].iov_len + iov[1].iov_len);

		/* FIXME: shortcat write, we do want to use NON-BLOCKING send here and
		 *        switch to write_ev should it block....
		 */
		if ((r = sendmsg(w->capwap_fd, &mh, MSG_DONTWAIT)) < 0)
			debug("sendmsg: %m");

		debug("fwd tap sendmsg: %zd", r);

		iov[1].iov_base = (unsigned char *)iov[1].iov_base + frag_size;
		offs += frag_size;
	}

	return 1;
}

static int ieee8023_to_sta(struct worker *w, const unsigned char *mac, const unsigned char *buffer, ssize_t len)
{
	struct station *sta;
	struct client *wtp = NULL;

	debug("STA MAC: " PRIsMAC, ARGsMAC(mac));

	rcu_read_lock();

	if ((sta = find_station(mac)) != NULL)
		wtp = rcu_dereference(sta->wtp);

	if (wtp) {
		/* the STA and WTP pointers are under RCU protection, so no-one will free them
		 * as long as we hold the RCU read lock */

		debug("found STA %p, WTP %p", sta, wtp);

		uatomic_inc(&sta->send_pkts);
		uatomic_add(&sta->send_bytes, len);

		/* queue packet to WTP */
		ieee8023_to_wtp(w, wtp, buffer, len);
	}

	rcu_read_unlock();

	return 1;
}

static int ieee8023_bcast_to_wtps(struct worker *w, const unsigned char *buffer, ssize_t len)
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *wtp;

	rcu_read_lock();

	cds_lfht_for_each_entry(ht_clients, &iter, wtp, node) {
		debug("WTP %p, stations: %d", wtp, uatomic_read(&wtp->sta_count));

		if (uatomic_read(&wtp->sta_count) != 0)
			/* queue packet to WTP */
			ieee8023_to_wtp(w, wtp, buffer, len);
	}

	rcu_read_unlock();

	return 1;
}

static void tap_multicast(struct worker *w, unsigned char *buffer, ssize_t len)
{
	struct ether_header *ether = (struct ether_header *)buffer;

	debug("dst mcast ether: " PRIsMAC, ARGsMAC(ether->ether_dhost));
	debug("ether mcast type: %04x", ntohs(ether->ether_type));

	switch (ntohs(ether->ether_type)) {
	case ETHERTYPE_IP: {
		ssize_t plen = len - sizeof(struct ether_header);
		struct iphdr *ip = (struct iphdr *)(ether + 1);

		if (plen != 0 && (ip->ihl * 4 + sizeof(struct udphdr)) < plen &&
		    ip->version == 4 && ip->protocol == IPPROTO_UDP) {
			struct udphdr *udp = (struct udphdr *)(((unsigned char *)ip) + ip->ihl * 4);

			plen -= ip->ihl * 4 + sizeof(struct udphdr);
			debug("UDP: plen: %zd, len: %d, source: %d, dest: %d", plen, ntohs(udp->len), ntohs(udp->source), ntohs(udp->dest));
			if (plen >= sizeof(struct dhcp_packet) && ntohs(udp->dest) == DHCP_CLIENT_PORT) {
				struct dhcp_packet *dhcp = (struct dhcp_packet *)(udp + 1);

				debug("DHCP: Op: %d, HType: %d, HLen: %d, CHADDR: " PRIsMAC, dhcp->op, dhcp->htype, dhcp->hlen, ARGsMAC(dhcp->chaddr));

				if (dhcp->htype == 1 && dhcp->hlen == 6) {
					/* forward DHCP broadcast to STA */
					if (ieee8023_to_sta(w, dhcp->chaddr, buffer, len))
						/* success */
						return;
				}
			}
		}
		break;
	}
	case ETHERTYPE_IPV6: {
		ssize_t plen = len - sizeof(struct ether_header);
		struct ip6_hdr *ip6 = (struct ip6_hdr *)(ether + 1);
		struct icmp6_hdr *icmp = (struct icmp6_hdr *)(ip6 + 1);

		if (plen >= (sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr)) &&
		    ip6->ip6_nxt == IPPROTO_ICMPV6 && icmp->icmp6_type == ND_ROUTER_ADVERT)
			if (ieee8023_bcast_to_wtps(w, buffer, len))
				/* success */
				return;

		break;
	}
	}

	packet_in_tap(buffer, len);
}

static void tap_unicast(struct worker *w, unsigned char *buffer, ssize_t len)
{
	struct ether_header *ether = (struct ether_header *)buffer;

	debug("dst unicast ether: " PRIsMAC, ARGsMAC(ether->ether_dhost));
	debug("ether unicast type: %04x", ntohs(ether->ether_type));

	if (!ieee8023_to_sta(w, ether->ether_dhost, buffer, len))
		packet_in_tap(buffer, len);
}

static void tap_cb(EV_P_ ev_io *ev, int revents)
{
	ssize_t r;
	unsigned char buffer[2048];
	int cnt = 10;
	struct worker *w = ev_userdata (EV_A);

	debug("read from %d", ev->fd);

	while (cnt > 0 && (r = read(ev->fd, buffer, sizeof(buffer))) > 0) {
		struct ether_header *ether = (struct ether_header *)&buffer;

		debug("read %zd bytes", r);
//		hexdump(buffer, r);

		if (r >= sizeof(struct ether_header)) {
			if ((ether->ether_dhost[0] & 0x01) != 0)
				tap_multicast(w, buffer, r);
			else
				tap_unicast(w, buffer, r);
		}

		cnt--;
	}

	if (r < 0) {
		if (errno == EAGAIN)
			return;
		perror("read");
	}
}

static void ev_lock(EV_P)
{
	struct worker *w = ev_userdata (EV_A);
	pthread_mutex_lock(&w->loop_lock);
}

static void ev_unlock(EV_P)
{
	struct worker *w = ev_userdata(EV_A);
	pthread_mutex_unlock (&w->loop_lock);
}

static int tap_alloc(char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if (fwd_ns_fd)
		fd = open_ns(fwd_ns_fd, "/dev/net/tun", O_RDWR);
	else
		fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		perror("open tun");
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (*dev != 0)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
	else
		strncpy(ifr.ifr_name, "tap%d", IFNAMSIZ - 1);

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	 */
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE;
	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		perror("ioctl");
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);

	debug("allocated TAP device %s", dev);
	return fd;
}

static void *worker_thread(void *arg)
{
	int on = 1;
	int domain;

	struct sockaddr_storage saddr;
	ssize_t saddr_len;
	struct worker *w = (struct worker *)arg;

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	memset(&saddr, 0, sizeof(saddr));
	if (v4only) {
		struct sockaddr_in *addr = (struct sockaddr_in *)&saddr;

		domain = AF_INET;
		addr->sin_family = AF_INET;
		addr->sin_port = htons(capwap_port);
		addr->sin_addr.s_addr = htonl(INADDR_ANY);
		saddr_len = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&saddr;

		domain = AF_INET6;
		addr->sin6_family = AF_INET6;
		addr->sin6_port = htons(capwap_port);
		// addr->sin6_addr = IN6ADDR_ANY;
		saddr_len = sizeof(struct sockaddr_in6);
	}

	if (capwap_ns_fd)
		w->capwap_fd = socket_ns(capwap_ns_fd, domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	else
		w->capwap_fd = socket(domain, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

	if (w->capwap_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(w->capwap_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
#if !defined(SO_REUSEPORT)
#       warning "SO_REUSEPORT undefined, please upgrade to a newer kernel"
#else
	setsockopt(w->capwap_fd, SOL_SOCKET, SO_REUSEPORT, (char*)&on, sizeof(on));
#endif
	setsockopt(w->capwap_fd, SOL_IP, IP_RECVERR, (char*)&on, sizeof(on));
	if (v6only)
		setsockopt(w->capwap_fd, SOL_IP, IPV6_V6ONLY,(char*)&on, sizeof(on));

	on = IP_PMTUDISC_DO;
	setsockopt(w->capwap_fd, SOL_IP, IP_MTU_DISCOVER,  (char*)&on, sizeof(on));

	if (bind(w->capwap_fd, (struct sockaddr *)&saddr, saddr_len) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	w->loop = ev_loop_new(EVFLAG_AUTO);

	ev_async_init(&w->stop_ev, stop_cb);
	ev_async_start(w->loop, &w->stop_ev);

	ev_io_init(&w->capwap_ev, capwap_cb, w->capwap_fd, EV_READ);
	ev_io_start(w->loop, &w->capwap_ev);

	fcntl(w->tap_fd, F_SETFL, O_NONBLOCK);
	ev_io_init(&w->tap_ev, tap_cb, w->tap_fd, EV_READ);
	ev_io_start(w->loop, &w->tap_ev);

	pthread_mutex_init(&w->loop_lock, 0);

	// now associate this with the loop
	ev_set_userdata(w->loop, w);
	ev_set_loop_release_cb(w->loop, ev_unlock, ev_lock);

	debug("worker running");

	ev_lock(w->loop);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	ev_run(w->loop, 0);
	ev_unlock(w->loop);

	ev_loop_destroy(w->loop);
	rcu_unregister_thread();

	debug("worker exited");

	return NULL;
}

int start_worker(size_t count)
{
	char tap_dev[IFNAMSIZ] = "\0";

	if (!(workers = calloc(count, sizeof(struct worker))))
		return 0;

	ht_clients = cds_lfht_new(1, 1, 0,
				  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				  NULL);
	ht_stations = cds_lfht_new(1, 1, 0,
				   CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
				   NULL);
	if (!ht_clients || !ht_stations)
		return 0;

	if (capwap_ns)
		capwap_ns_fd = get_nsfd(capwap_ns);
	if (fwd_ns)
		fwd_ns_fd = get_nsfd(fwd_ns);

	num_workers = count;
	for (int i = 0; i < count; i++) {
		workers[i].id = i;
		workers[i].unknown_wtp_limit.interval = unknown_wtp_limit_interval;
		workers[i].unknown_wtp_limit.bucket = unknown_wtp_limit_bucket;

		if ((workers[i].tap_fd = tap_alloc(tap_dev)) < 0)
			return 0;
		pthread_create(&workers[i].tid, NULL, worker_thread, (void *)&workers[i]);
	}

	return 1;
}
