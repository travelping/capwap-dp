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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define _REENTRANT

#include <assert.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <urcu.h>            /* RCU flavor */
#include <urcu/uatomic.h>
#include <urcu/ref.h>		 /* ref counting */
#include <urcu/rculist.h>    /* RCU list */
#include <urcu/rculfqueue.h> /* RCU Lock-free queue */
#include <urcu/rculfhash.h>	 /* RCU Lock-free hash table */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "jhash.h"

#include <libconfig.h>

#include <ev.h>

#ifdef USE_SYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif

#include "ei.h"

void* ei_malloc (long size);

#include "log.h"
#include "capwap-dp.h"
#include "netns.h"
#include "dhcp_internal.h"
#include "ieee8023.h"

#define API_VERSION      1

static const char _ident[] = "capwap-dp v" VERSION;
static const char _build[] = "built on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct control_loop {
	struct ev_loop *loop;
	pthread_mutex_t loop_lock; /* global loop lock */

	int listen_fd;
	ev_io control_ev;

	struct cds_lfq_queue_rcu queue;
	ev_async q_ev;
};

static struct control_loop ctrl;

/* worker used for sendto and packet_out,
 * only the control thread is access this variable */
static int send_worker = 0;

struct controller {
	struct rcu_head rcu_head;       /* For call_rcu() */
	struct cds_list_head controllers;

	int fd;
	int dhcp_fd;
	ErlConnect conp;

	ev_io ev_read;
	// write_lock

	erlang_pid bind_pid;

	ei_x_buff x_in;
	ei_x_buff x_out;
};

/* 
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct udp_pheader
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

CDS_LIST_HEAD(controllers);
static ei_cnode ec;

static int ei_x_new_size(ei_x_buff* x, long size)
{
#define BLK_MAX 127

	size = (size + BLK_MAX) & ~BLK_MAX;

#undef BLK_MAX

	x->buff = ei_malloc(size);
	x->buffsz = size;
	x->index = 0;
	return x->buff != NULL ? 0 : -1;

}

static int ei_decode_sockaddr_ipv4(const char *buf, int *index, struct sockaddr_in *addr)
{
	uint32_t a = 0;

	for (int i = 0; i < 4; i++) {
		unsigned long p;
		if (ei_decode_ulong(buf, index, &p) != 0)
			return -1;
		a = a << 8;
		a |= p;
	}

	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(a);

	return 0;
}

static int ei_decode_sockaddr_ipv6_v4mapped(const char *buf, int *index, struct sockaddr_in6 *addr)
{
	uint32_t a = 0;

	for (int i = 0; i < 4; i++) {
		unsigned long p;
		if (ei_decode_ulong(buf, index, &p) != 0)
			return -1;
		a = a << 8;
		a |= p;
	}

	addr->sin6_family = AF_INET6;
	addr->sin6_addr.s6_addr32[0] = 0;
	addr->sin6_addr.s6_addr32[1] = 0;
	addr->sin6_addr.s6_addr32[2] = htonl(0xffff);
	addr->sin6_addr.s6_addr32[3] = htonl(a);

	return 0;
}

static int ei_decode_sockaddr_ipv6(const char *buf, int *index, struct sockaddr_in6 *addr)
{
	addr->sin6_family = AF_INET6;

	for (int i = 0; i < 8; i++) {
		unsigned long p;
		if (ei_decode_ulong(buf, index, &p) != 0)
			return -1;
		addr->sin6_addr.s6_addr16[i] = htons(p);
	}

	return 0;
}

static int ei_decode_sockaddr_ip(const char *buf, int *index, struct sockaddr_storage *addr)
{
	int r = -1;
	int arity;

	if (ei_decode_tuple_header(buf, index, &arity) != 0)
		return -1;

	switch (arity) {
	case 4:
		if (!v4only)
			r = ei_decode_sockaddr_ipv6_v4mapped(buf, index, (struct sockaddr_in6 *)addr);
		else
			r = ei_decode_sockaddr_ipv4(buf, index, (struct sockaddr_in *)addr);
		break;

	case 8:
		r = ei_decode_sockaddr_ipv6(buf, index, (struct sockaddr_in6 *)addr);
		break;
	}
	return r;
}

static int ei_decode_sockaddr(const char *buf, int *index, struct sockaddr_storage *addr)
{
	int arity;
	unsigned long port;

	memset(addr, 0, sizeof(struct sockaddr_storage));

	if (ei_decode_tuple_header(buf, index, &arity) != 0
	    || arity != 2
	    || ei_decode_sockaddr_ip(buf, index, addr)
	    || ei_decode_ulong(buf, index, &port))
	    return -1;

	switch (addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		in->sin_port = htons(port);
		break;
	}

	case AF_INET6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;
		in6->sin6_port = htons(port);
		break;
	}
	}

	debug_sockaddr(addr);

	return 0;
}

static void ei_x_encode_sockaddr(ei_x_buff *x, const struct sockaddr *addr)
{
	debug_sockaddr(addr);

	ei_x_encode_tuple_header(x, 2);

	switch (addr->sa_family) {
	case AF_INET: {
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		uint8_t *a = (uint8_t *)&in->sin_addr.s_addr;

		ei_x_encode_tuple_header(x, 4);
		for (int i = 0; i < 4; i++)
			ei_x_encode_ulong(x, a[i]);
		ei_x_encode_ulong(x, ntohs(in->sin_port));
		break;
	}

	case AF_INET6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			uint8_t *a = (uint8_t *)&in6->sin6_addr.s6_addr32[3];

			ei_x_encode_tuple_header(x, 4);
			for (int i = 0; i < 4; i++)
				ei_x_encode_ulong(x, a[i]);
		} else {
			ei_x_encode_tuple_header(x, 8);
			for (int i = 0; i < 8; i++)
				ei_x_encode_ulong(x, ntohs(in6->sin6_addr.s6_addr16[i]));
		}
		ei_x_encode_ulong(x, ntohs(in6->sin6_port));
		break;
	}
	}
}

static int ei_decode_ether(const char *buf, int *index, uint8_t *ether)
{
	long len;

	if (ei_decode_binary(buf, index, ether, &len) != 0
	    || len != ETH_ALEN)
		return -1;

	debug("MAC: " PRIsMAC, ARGsMAC(ether));

	return 0;
}

static void ei_x_encode_ether(ei_x_buff *x, uint8_t *ether)
{
	debug("MAC: " PRIsMAC, ARGsMAC(ether));

	ei_x_encode_binary(x, (void *)ether, ETH_ALEN);
}

static void ei_x_encode_wlan(ei_x_buff *x, struct wlan *wlan)
{
	ei_x_encode_tuple_header(x, 4);
	ei_x_encode_ulong(x, wlan->rid);
	ei_x_encode_ulong(x, wlan->wlan_id);
	ei_x_encode_ether(x, wlan->bssid);
	ei_x_encode_ulong(x, wlan->vlan);
}

static void ei_x_encode_sta(ei_x_buff *x, struct station *sta)
{
	ei_x_encode_tuple_header(x, 5);
	ei_x_encode_ether(x, sta->ether);
	ei_x_encode_ulong(x, sta->vlan);
	ei_x_encode_ulong(x, sta->rid);
	ei_x_encode_ether(x, sta->bssid);
	ei_x_encode_tuple_header(x, 4);
	ei_x_encode_longlong(x, uatomic_read(&sta->rcvd_pkts));
	ei_x_encode_longlong(x, uatomic_read(&sta->send_pkts));
	ei_x_encode_longlong(x, uatomic_read(&sta->rcvd_bytes));
	ei_x_encode_longlong(x, uatomic_read(&sta->send_bytes));
}

static void ei_x_encode_wtp(ei_x_buff *x, struct client *clnt)
{
	struct station *sta;
	struct wlan *wlan;

	ei_x_encode_tuple_header(x, 6);
	ei_x_encode_sockaddr(x, (struct sockaddr *)&clnt->addr);
	cds_hlist_for_each_entry_rcu_2(wlan, &clnt->wlans, wlan_list) {
		ei_x_encode_list_header(x, 1);
		ei_x_encode_wlan(x, wlan);
	}
	ei_x_encode_empty_list(x);
	cds_hlist_for_each_entry_rcu_2(sta, &clnt->stations, wtp_list) {
		ei_x_encode_list_header(x, 1);
		ei_x_encode_sta(x, sta);
	}
	ei_x_encode_empty_list(x);
	ei_x_encode_longlong(x, clnt->ref.refcount);
	ei_x_encode_longlong(x, clnt->mtu);
	ei_x_encode_tuple_header(x, 9);

	ei_x_encode_longlong(x, uatomic_read(&clnt->rcvd_pkts));
	ei_x_encode_longlong(x, uatomic_read(&clnt->send_pkts));
	ei_x_encode_longlong(x, uatomic_read(&clnt->rcvd_bytes));
	ei_x_encode_longlong(x, uatomic_read(&clnt->send_bytes));

	ei_x_encode_longlong(x, uatomic_read(&clnt->rcvd_fragments));
	ei_x_encode_longlong(x, uatomic_read(&clnt->send_fragments));

	ei_x_encode_longlong(x, uatomic_read(&clnt->err_invalid_station));
	ei_x_encode_longlong(x, uatomic_read(&clnt->err_fragment_invalid));
	ei_x_encode_longlong(x, uatomic_read(&clnt->err_fragment_too_old));
}

static void cnt_send(struct controller *cnt, ei_x_buff *x)
{
	int r __attribute__((unused));

#if defined(DEBUG)
	{
		int index = 0;
		char *s = NULL;
		int version;

		ei_decode_version(x->buff, &index, &version);
		ei_s_print_term(&s, x->buff, &index);
		debug("Msg-Out: %d, %s", index, s);
		free(s);

		hexdump((const unsigned char *)x->buff, x->index);
	}
#endif

	r = ei_send(cnt->fd, &cnt->bind_pid, x->buff, x->index);
	debug("send ret: %d", r);
}

static void erl_send_to(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	ssize_t r __attribute__((unused));
	struct client *clnt;
	struct sockaddr_storage addr;
	const char *bin;
	long bin_len;

	if (arity != 3) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_binary(x_in->buff, &x_in->index, NULL, &bin_len) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}
	bin = x_in->buff + x_in->index - bin_len;

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) != NULL) {

		debug_sockaddr(&clnt->addr);

		assert(memcmp(&addr, &clnt->addr, clnt->addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == 0);

		uatomic_inc(&workers[send_worker].send_pkts);
		uatomic_inc(&clnt->send_pkts);
		uatomic_add(&workers[send_worker].send_bytes, bin_len);
		uatomic_add(&clnt->send_bytes, bin_len);

		if (bin_len > CAPWAP_HEADER_LEN &&
		    GET_CAPWAP_HEADER_FIELD(bin, CAPWAP_F_FRAG, 0)) {
			uatomic_inc(&workers[send_worker].send_fragments);
			uatomic_inc(&clnt->send_fragments);
		}

		r = sendto(workers[send_worker].capwap_fd, bin, bin_len, 0,
			   (struct sockaddr *)&clnt->addr, sizeof(clnt->addr));
		debug("erl_send_to: %zd", r);

		send_worker = (send_worker + 1) % num_workers;
	} else
		log(LOG_DEBUG, "failed to find client: %p", clnt);

	rcu_read_unlock();

	ei_x_encode_atom(x_out, "ok");
}

static void erl_packet_out(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	char dst[MAXATOMLEN+1] = {0};
	unsigned long vlan;
	ssize_t r __attribute__((unused));
	const char *bin;
	long bin_len;
	struct iovec iov[3];
	uint16_t vlan_tag[2];
	int i, n;

	if (arity != 4) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_atom(x_in->buff, &x_in->index, dst) < 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &vlan) != 0
	    || vlan > UINT16_MAX
	    || ei_decode_binary(x_in->buff, &x_in->index, NULL, &bin_len) != 0
	    || bin_len < sizeof(struct ether_header)) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	bin = x_in->buff + x_in->index - bin_len;

	n = 0;

	/* FIXME: shortcat write */
	iov[n].iov_base = (unsigned char *)bin;
	iov[n].iov_len = ETH_ALEN * 2;
	n++;

	if (vlan != 0) {
		vlan_tag[0] = htons(ETHERTYPE_VLAN);
		vlan_tag[1] = htons(vlan);

		iov[n].iov_base = vlan_tag;
		iov[n].iov_len = 4;
		n++;
	}

	iov[n].iov_base = (unsigned char *)bin + (ETH_ALEN * 2);
	iov[n].iov_len = bin_len - 12;
	n++;

	for (i = 0; i < n; i++)
		hexdump(iov[i].iov_base, iov[i].iov_len);

	if ((r = writev(workers[send_worker].tap_fd, iov, n)) < 0) {
		debug("writev: %m");
	}
	debug("erl_send_to writev: %zd", r);

	ei_x_encode_atom(x_out, "ok");
}

static void erl_bind(struct controller *cnt, int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	if (arity != 2
	    || ei_decode_pid(x_in->buff, &x_in->index, &cnt->bind_pid) != 0)
		ei_x_encode_atom(x_out, "badarg");
	else {
		ei_x_encode_tuple_header(x_out, 2);
		ei_x_encode_atom(x_out, "ok");
		ei_x_encode_ulong(x_out, API_VERSION);
	}
}

static void erl_clear(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *wtp;

	if (arity != 1) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	cds_lfht_for_each_entry(ht_clients, &iter, wtp, node)
		__delete_wtp(wtp);

	rcu_read_unlock();

	ei_x_encode_atom(x_out, "ok");
}

static void erl_add_wtp(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct sockaddr_storage addr;
	unsigned long mtu;

	if (arity != 3) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &mtu) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (!add_wtp((struct sockaddr *)&addr, mtu))
		ei_x_encode_atom(x_out, "enomem");
	else
		ei_x_encode_atom(x_out, "ok");
}

static void erl_del_wtp(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct sockaddr_storage addr;
	struct client *wtp;

	if (arity != 2) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((wtp = find_wtp((struct sockaddr *)&addr)) != NULL) {
		if (!__delete_wtp(wtp))
			ei_x_encode_atom(x_out, "failed");
		else {
			ei_x_encode_tuple_header(x_out, 2);
			ei_x_encode_atom(x_out, "ok");
			ei_x_encode_wtp(x_out, wtp);
		}
	} else
		ei_x_encode_atom(x_out, "not_found");

	rcu_read_unlock();

}

static void erl_list_wtp(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *clnt;

	if (arity != 1) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();
	cds_lfht_for_each_entry(ht_clients, &iter, clnt, node) {
		ei_x_encode_list_header(x_out, 1);
		ei_x_encode_wtp(x_out, clnt);
	}
	rcu_read_unlock();
	ei_x_encode_empty_list(x_out);
}

static void erl_get_wtp(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct client *clnt;
	struct sockaddr_storage addr;

	if (arity != 2) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) != NULL) {
		ei_x_encode_wtp(x_out, clnt);
	} else
		ei_x_encode_atom(x_out, "not_found");

	rcu_read_unlock();
}

static struct wlan *find_wlan(struct client *clnt, unsigned long rid, unsigned long wlan_id)
{
	struct wlan *wlan;

	cds_hlist_for_each_entry_2(wlan, &clnt->wlans, wlan_list) {
		if (wlan->rid == rid && wlan->wlan_id == wlan_id)
			return wlan;
	}

	return NULL;
}

static void erl_add_wlan(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct wlan *wlan;
	struct client *clnt;
	struct sockaddr_storage addr;
	unsigned long rid;
	unsigned long wlan_id;
	uint8_t bssid[ETH_ALEN];
	unsigned long vlan;

	if (arity != 6) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &rid) != 0
	    || rid == 0 || rid >= MAX_RADIOS
	    || ei_decode_ulong(x_in->buff, &x_in->index, &wlan_id) != 0
	    || wlan_id == 0 || wlan_id >= MAX_WLANS
	    || ei_decode_ether(x_in->buff, &x_in->index, bssid) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &vlan) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) == NULL) {
		ei_x_encode_atom(x_out, "not_found");
		goto out_unlock;
	}

	if (find_wlan(clnt, rid, wlan_id) != NULL) {
		ei_x_encode_atom(x_out, "duplicate");
		goto out_unlock;
	}

	wlan = calloc(1, sizeof(struct wlan));
	if (!wlan) {
		ei_x_encode_atom(x_out, "enomem");
		goto out_unlock;
	}

	wlan->rid = rid;
	wlan->wlan_id = wlan_id;
	memcpy(&wlan->bssid, &bssid, sizeof(bssid));
	wlan->vlan = vlan;

	/*
	 * list mutating operations need mutal exclusion,
	 * this is currently guaranteed since only the
	 * control thread is permitted to call this
	 */
	cds_hlist_add_head_rcu(&wlan->wlan_list, &clnt->wlans);

	ei_x_encode_atom(x_out, "ok");

out_unlock:
	rcu_read_unlock();
}

static void erl_del_wlan(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct wlan *wlan;
	struct client *clnt;
	struct sockaddr_storage addr;
	unsigned long rid;
	unsigned long wlan_id;

	if (arity != 3) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &rid) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &wlan_id) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) == NULL) {
		ei_x_encode_atom(x_out, "not_found");
		goto out_unlock;
	}

	if ((wlan = find_wlan(clnt, rid, wlan_id)) != NULL) {
		__delete_wlan(wlan);
		ei_x_encode_atom(x_out, "ok");
	} else
		ei_x_encode_atom(x_out, "not_found");

out_unlock:
	rcu_read_unlock();
}

static void erl_attach_station(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct station *sta;
	struct client *clnt;
	struct sockaddr_storage addr;
	uint8_t ether[ETH_ALEN];
	unsigned long vlan;
	unsigned long rid;
	uint8_t bssid[ETH_ALEN];

	unsigned long hash;

	if (arity != 6) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_sockaddr(x_in->buff, &x_in->index, &addr) != 0
	    || ei_decode_ether(x_in->buff, &x_in->index, ether) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &vlan) != 0
	    || ei_decode_ulong(x_in->buff, &x_in->index, &rid) != 0
	    || ei_decode_ether(x_in->buff, &x_in->index, bssid) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if (find_station(ether) != NULL) {
		ei_x_encode_atom(x_out, "duplicate");
		goto out_unlock;
	}

	if ((clnt = find_wtp((struct sockaddr *)&addr)) == NULL) {
		ei_x_encode_atom(x_out, "not_found");
		goto out_unlock;
	}

	hash = jhash(ether, ETH_ALEN, 0x12345678);

	sta = calloc(1, sizeof(struct station));
	if (!sta) {
		ei_x_encode_atom(x_out, "enomem");
		goto out_unlock;
	}

	urcu_ref_init(&sta->ref);
	cds_lfht_node_init(&sta->station_hash);
	memcpy(&sta->ether, &ether, sizeof(ether));
	sta->vlan = vlan;
	sta->rid = rid;
	memcpy(&sta->bssid, &bssid, sizeof(bssid));

	/*
	 * Mutating operations need mutal exclusion from each other,
	 * only concurrent reads are allowed.
	 * This is currently guaranteed since only the
	 * control thread is permitted to call this.
	 */
	cds_lfht_add(ht_stations, hash, &sta->station_hash);
	attach_station_to_wtp(clnt, sta);

	ei_x_encode_atom(x_out, "ok");

out_unlock:
	rcu_read_unlock();
}

static void erl_detach_station(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct station *sta;
	uint8_t ether[ETH_ALEN];

	if (arity != 2) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_ether(x_in->buff, &x_in->index, ether) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((sta = find_station(ether)) != NULL) {
		if (__delete_station(sta) == 0) {
			ei_x_encode_tuple_header(x_out, 2);
			ei_x_encode_atom(x_out, "ok");
			ei_x_encode_sta(x_out, sta);
		} else {
			ei_x_encode_atom(x_out, "hash_corrupt");
		}
	} else
		ei_x_encode_atom(x_out, "not_found");

	rcu_read_unlock();
}

static void erl_get_station(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct station *sta;
	uint8_t ether[ETH_ALEN];

	if (arity != 2) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	if (ei_decode_ether(x_in->buff, &x_in->index, ether) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();

	if ((sta = find_station(ether)) != NULL) {
		ei_x_encode_sta(x_out, sta);
	} else
		ei_x_encode_atom(x_out, "not_found");

	rcu_read_unlock();
}

static void erl_list_stations(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct station *sta;

	if (arity != 1) {
		ei_x_encode_atom(x_out, "badarg");
		return;
	}

	rcu_read_lock();
        cds_lfht_for_each_entry(ht_stations, &iter, sta, station_hash) {
		ei_x_encode_list_header(x_out, 1);
		ei_x_encode_sta(x_out, sta);

	}
	rcu_read_unlock();
	ei_x_encode_empty_list(x_out);
}

static void erl_get_stats(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	ei_x_encode_list_header(x_out, num_workers);
	for (int i = 0; i < num_workers; i++) {
		ei_x_encode_tuple_header(x_out, 13);

		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].rcvd_pkts));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].send_pkts));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].rcvd_bytes));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].send_bytes));

		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].rcvd_fragments));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].send_fragments));

		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_invalid_station));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_fragment_invalid));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_fragment_too_old));

		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_invalid_wtp));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_hdr_length_invalid));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].err_too_short));
		ei_x_encode_longlong(x_out, uatomic_read(&workers[i].ratelimit_unknown_wtp));
	}
	ei_x_encode_empty_list(x_out);
}

unsigned short csum(unsigned short *ptr,int nbytes)
{
    register long sum = 0;
    unsigned short oddbyte;

    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);

    return ~sum;
}

static struct iphdr* fill_raw_udp_packet(char *send_data, size_t data_len,
        size_t* len)
{
    char datagram[4096], source_ip[32], *data, *pseudogram;
    struct iphdr *iph = (struct iphdr *) (datagram + sizeof(struct ether_header));
    //UDP header
    struct udphdr *udph = (struct udphdr *) (datagram +
            sizeof (struct iphdr) + sizeof(struct ether_header));

    // zero out the packet buffer
    // NOTE: all size for packet
    memset(datagram, 0, 4096);

    data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
    strncpy(data, send_data, data_len);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct iphdr) + sizeof (struct udphdr) + strlen(data);
    iph->id = htonl(54321); //Id of this packet
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;      //Set to 0 before calculating checksum
    // Source ip
    iph->saddr = inet_addr ( source_ip );    //Spoof the source ip address
    // Dest ip
    iph->daddr = sin.sin_addr.s_addr;

    //Ip checksum
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);

    //UDP header
    udph->source = htons (6666);
    udph->dest = htons (8622);
    udph->len = htons(8 + strlen(data)); //tcp header size
    udph->check = 0; //leave checksum 0 now, filled later by pseudo header

    //Now the UDP checksum using the pseudo header
    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + strlen(data) );

    int psize = sizeof(struct udp_pheader) + sizeof(struct udphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram , (char*) &psh, sizeof (struct udp_pheader));
    memcpy(pseudogram + sizeof(struct udp_pheader), udph,
            sizeof(struct udphdr) + strlen(data));

    udph->check = csum( (unsigned short*) pseudogram , psize);

	// Packet data
    //
    free(pseudogram);

    return iph;
}

static void erl_send_dhcp_packet(int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	struct dhcp_packet *bin;
	long bin_len;
	/* struct sockaddr_in daddr; */

    debug("Receive dhcp packet");
    if (arity != 2) {
		ei_x_encode_atom(x_out, "badarg");
		return;
    }

	if (ei_decode_binary(x_in->buff, &x_in->index, NULL, &bin_len) != 0) {
		ei_x_encode_atom(x_out, "badarg");
		return;
    }
    bin = (struct dhcp_packet*)(x_in->buff + x_in->index - bin_len);
    debug(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
    hexdump(bin, bin_len);
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(bin->yiaddr), str, INET_ADDRSTRLEN);
    debug("y======================: %s", str);
    inet_ntop(AF_INET, &(bin->giaddr), str, INET_ADDRSTRLEN);
    debug("my======================: %s", str);

    if (bin->op == BOOTREPLY) {
    // Msg from client

    if (bin->flags & F_BROADCAST) {
        debug("broadcast answer");

		/* struct in_pktinfo *pkt; */

		/* msg.msg_control = cbuf; */
		/* msg.msg_controllen = sizeof(cbuf); */

		/* cmsg = CMSG_FIRSTHDR(&msg); */

		/* pkt = (struct in_pktinfo *)CMSG_DATA(cmsg); */
		/* pkt->ipi_ifindex = if_idx; */
		/* pkt->ipi_spec_dst.s_addr = INADDR_ANY; */

		/* msg.msg_controllen = cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo)); */

		/* cmsg->cmsg_level = SOL_IP; */
		/* cmsg->cmsg_type = IP_PKTINFO; */
		/* daddr.sin_port = htons(68); */
		/* daddr.sin_addr.s_addr = INADDR_BROADCAST; */
    } else {
		debug("unicast answer");

        debug("Send offer to iface %s", tap_dev);

        /* daddr.sin_port = htons(68); */
        /* daddr.sin_addr = bin->yiaddr; */

        /* /1* unicast to unconfigured client */
        /*  * inject MAC address direct into ARP cache *1/ */
        /* struct arpreq arp; */
        /* *((struct sockaddr_in *)&arp.arp_pa) = daddr; */
        /* daddr.sin_family = AF_INET; */

        /* arp.arp_ha.sa_family = bin->htype; */
        /* /1* arp.arp_ha.sa_family = AF_UNSPEC; *1/ */
        /* memcpy(arp.arp_ha.sa_data, bin->chaddr, bin->hlen); */
        /* strncpy(arp.arp_dev, tap_dev, IFNAMSIZ); */
        /* arp.arp_flags = ATF_COM; */
        /* ssize_t r __attribute__((unused)); */

        /* r = ioctl(workers[send_worker].dhcp_fd, SIOCSARP, &arp); */
        /* debug("arp result: %zd", r); */


        /* r = sendto(workers[send_worker].dhcp_fd, bin, bin_len, 0, &daddr, sizeof(daddr)); */
        /* debug("offer sendto: %zd", r); */

        /*mac */
        /* bin->chaddr */
        struct iphdr *iph;
        size_t send_len;
        iph = fill_raw_udp_packet(bin, bin_len, &send_len);
        ieee8023_to_sta(&workers[send_worker], "9c:a9:e4:12:7d:b3", 0,
                (const unsigned char *)iph, send_len);
    }
    }

	ei_x_encode_atom(x_out, "ok");
}

static void handle_gen_call_capwap(struct controller *cnt, const char *fn, int arity, ei_x_buff *x_in, ei_x_buff *x_out)
{
	if (strncmp(fn, "sendto", 6) == 0) {
		erl_send_to(arity, x_in, x_out);
	}
	if (strncmp(fn, "packet_out", 10) == 0) {
		erl_packet_out(arity, x_in, x_out);
	}
	if (strncmp(fn, "bind", 4) == 0) {
		erl_bind(cnt, arity, x_in, x_out);
	}
	if (strncmp(fn, "clear", 4) == 0) {
		erl_clear(arity, x_in, x_out);
	}
	if (strncmp(fn, "add_wtp", 7) == 0) {
		erl_add_wtp(arity, x_in, x_out);
	}
	else if (strncmp(fn, "del_wtp", 7) == 0) {
		erl_del_wtp(arity, x_in, x_out);
	}
	else if (strncmp(fn, "list_wtp", 8) == 0) {
		erl_list_wtp(arity, x_in, x_out);
	}
	else if (strncmp(fn, "get_wtp", 7) == 0) {
		erl_get_wtp(arity, x_in, x_out);
	}
	if (strncmp(fn, "add_wlan", 8) == 0) {
		erl_add_wlan(arity, x_in, x_out);
	}
	else if (strncmp(fn, "del_wlan", 8) == 0) {
		erl_del_wlan(arity, x_in, x_out);
	}
	else if (strncmp(fn, "attach_station", 14) == 0) {
		erl_attach_station(arity, x_in, x_out);
	}
	else if (strncmp(fn, "detach_station", 14) == 0) {
		erl_detach_station(arity, x_in, x_out);
	}
	else if (strncmp(fn, "get_station", 11) == 0) {
		erl_get_station(arity, x_in, x_out);
	}
	else if (strncmp(fn, "list_stations", 13) == 0) {
		erl_list_stations(arity, x_in, x_out);
	}
	else if (strncmp(fn, "get_stats", 9) == 0) {
		erl_get_stats(arity, x_in, x_out);
	}
	else if (strncmp(fn, "send_dhcp_packet", 16) == 0) {
		erl_send_dhcp_packet(arity, x_in, x_out);
	}
	else
		ei_x_encode_atom(x_out, "error");
}

static void handle_gen_call(struct controller *cnt, const char *to, ei_x_buff *x_in)
{
	ei_x_buff *x_out = &cnt->x_out;
	int arity;
	erlang_pid pid;
	erlang_ref ref;
	char fn[MAXATOMLEN+1] = {0};
	int r __attribute__((unused));

	/* decode From tupple */
	if (ei_decode_tuple_header(x_in->buff, &x_in->index, &arity) < 0
	    || arity != 2
	    || ei_decode_pid(x_in->buff, &x_in->index, &pid) < 0
	    || ei_decode_ref(x_in->buff, &x_in->index, &ref) < 0) {
		debug("Ignoring malformed message.");
		log(LOG_WARNING, "Ignoring malformed message.");
		return;
	}

	/* decode call args */
	if (ei_decode_tuple_header(x_in->buff, &x_in->index, &arity) < 0
	    || ei_decode_atom(x_in->buff, &x_in->index, fn) < 0) {
		debug("Ignoring malformed message.");
		log(LOG_WARNING, "Ignoring malformed message.");
		return;
	}

	ei_x_encode_version(x_out);
	ei_x_encode_tuple_header(x_out, 2);
	ei_x_encode_ref(x_out, &ref);

	if (strncmp(to, "net_kernel", 10) == 0 &&
	    strncmp(fn, "is_auth", 7) == 0) {
		ei_x_encode_atom(x_out, "yes");
	}
	else if (strncmp(to, "capwap", 6) == 0) {
		handle_gen_call_capwap(cnt, fn, arity, x_in, x_out);
	}
	else
		ei_x_encode_atom(x_out, "error");

#if defined(DEBUG)
	{
		int index = 0;
		char *s = NULL;
		int version;

		ei_decode_version(x_out->buff, &index, &version);
		ei_s_print_term(&s, x_out->buff, &index);
		debug("Msg-Out: %d, %s", index, s);
		free(s);
	}
#endif

	r = ei_send(cnt->fd, &pid, x_out->buff, x_out->index);
	debug("send ret: %d", r);
}

static void handle_gen_cast(struct controller *cnt, const char *to, ei_x_buff *x_in)
{
}

static void handle_msg(struct controller *cnt, const char *to, ei_x_buff *x_in)
{
	int version;
	int arity;
	char type[MAXATOMLEN+1] = {0};

	debug("Msg to: %s, ", to);

	x_in->index = 0;

	if (ei_decode_version(x_in->buff, &x_in->index, &version) < 0) {
		debug("Ignoring malformed message (bad version: %d).", version);
		log(LOG_WARNING, "Ignoring malformed message (bad version: %d).", version);
		return;
	}

#if defined(DEBUG)
	{
		int index = x_in->index;
		char *s = NULL;

		ei_s_print_term(&s, x_in->buff, &index);
		debug("Msg-In: %d, %s", index, s);
		free(s);
	}
#endif

	if (ei_decode_tuple_header(x_in->buff, &x_in->index, &arity) < 0
	    || ei_decode_atom(x_in->buff, &x_in->index, type) < 0) {
		debug("Ignoring malformed message.");
		log(LOG_WARNING, "Ignoring malformed message.");
		return;
	}

	debug("Type: %s\n", type);

	if (arity == 3 && strncmp(type, "$gen_call", 9) == 0) {
		handle_gen_call(cnt, to, x_in);
	}
	else if (arity == 2 && strncmp(type, "$gen_cast", 9) == 0) {
		handle_gen_cast(cnt, to, x_in);
	}
	else
		log(LOG_WARNING, "Ignoring Msg %s.", type);
}

static void free_controller(struct rcu_head *head)
{
	struct controller *cnt = caa_container_of(head, struct controller, rcu_head);

	ei_x_free(&cnt->x_in);
	ei_x_free(&cnt->x_out);
	free(cnt);
}

static void erl_read_cb(EV_P_ ev_io *w, int revents)
{
	struct controller *cnt = caa_container_of(w, struct controller, ev_read);
	erlang_msg msg;
	int r;

	ei_x_buff *x_in = &cnt->x_in;
	ei_x_buff *x_out = &cnt->x_out;

	x_out->index = x_in->index = 0;

	r = ei_xreceive_msg(w->fd, &msg, x_in);
	if (r == ERL_TICK) {
		debug("DEBUG: TICK");
		/* ignore */
	} else if (r == ERL_ERROR) {
		log(LOG_ERR, "ERROR on fd %d, %s (%d)", w->fd, strerror(erl_errno), erl_errno);
		cnt->fd = -1;
		close(w->fd);
		ev_io_stop (EV_A_ w);

		cds_list_del_rcu(&cnt->controllers);
		call_rcu(&cnt->rcu_head, free_controller);
	} else {
		switch (msg.msgtype) {
		case ERL_SEND:
		case ERL_REG_SEND:
			handle_msg(cnt, msg.toname, x_in);
			break;

		default:
			debug("msg.msgtype: %ld", msg.msgtype);
			break;
		}
	}
}

static void control_cb(EV_P_ ev_io *w, int revents)
{
	struct controller *cnt;

	if (!(cnt = calloc(1, sizeof(struct controller))))
		return;

	if ((cnt->fd = ei_accept_tmo(&ec, w->fd, &cnt->conp, 100)) == ERL_ERROR) {
		log(LOG_WARNING, "Failed to ei_accept on fd %d with %s (%d)", w->fd, strerror(erl_errno), erl_errno);
		free(cnt);
		return;
	}

	debug("ei_accept, got fd %d (%d)", cnt->fd, erl_errno);

	/* prealloc enough space to hold a full CAPWAP PDU plus Erlang encoded meta data */
	ei_x_new_size(&cnt->x_in, 2048);
	ei_x_new_size(&cnt->x_out, 2048);

	ev_io_init(&cnt->ev_read, erl_read_cb, cnt->fd, EV_READ);
	ev_io_start(EV_A_ &cnt->ev_read);

	cds_list_add_rcu(&cnt->controllers, &controllers);
}

struct cq_node {
	ei_x_buff x;

	struct cds_lfq_node_rcu node;
	struct rcu_head rcu_head;       /* For call_rcu() */
};

static void free_qnode(struct rcu_head *head)
{
	struct cq_node *node = caa_container_of(head, struct cq_node, rcu_head);

	ei_x_free(&node->x);
	free(node);
}

static void control_enqueue(ei_x_buff *x)
{
	struct cq_node *cq;

	cq = calloc(1, sizeof(struct cq_node));
	if (!cq)
		return;

	cds_lfq_node_init_rcu(&cq->node);
	memcpy(&cq->x, x, sizeof(ei_x_buff));

	/*
	 * Both enqueue and dequeue need to be called within RCU
	 * read-side critical section.
	 */
	rcu_read_lock();
	cds_lfq_enqueue_rcu(&ctrl.queue, &cq->node);
	rcu_read_unlock();

	ev_async_send(ctrl.loop, &ctrl.q_ev);
}

static void q_cb(EV_P_ ev_async *ev, int revents)
{
	struct control_loop *w = ev_userdata(EV_A);

	for (;;) {
		struct cds_lfq_node_rcu *qnode;
		struct cq_node *cq;
		struct controller *cnt;

		/*
		 * Both enqueue and dequeue need to be called within RCU
		 * read-side critical section.
		 */
		rcu_read_lock();
		qnode = cds_lfq_dequeue_rcu(&w->queue);
		rcu_read_unlock();
		if (!qnode) {
			break;  /* Queue is empty. */
		}

		/* Getting the container structure from the node */
		cq = caa_container_of(qnode, struct cq_node, node);

		/*
		 * we don't need RCU protection here, no one else can access the list
		 */
		cds_list_for_each_entry_rcu(cnt, &controllers, controllers) {
			cnt_send(cnt, &cq->x);
		}

		call_rcu(&cq->rcu_head, free_qnode);
	}
}

void capwap_socket_error(int origin, int type, const struct sockaddr *addr)
{
	ei_x_buff x;

	ei_x_new(&x);
	ei_x_encode_version(&x);
	ei_x_encode_tuple_header(&x, 4);
	ei_x_encode_atom(&x, "capwap_error");
	ei_x_encode_ulong(&x, origin);
	ei_x_encode_ulong(&x, type);
	ei_x_encode_sockaddr(&x, addr);

	control_enqueue(&x);
}

void capwap_in(const struct sockaddr *addr,
	       const unsigned char *radio_mac, unsigned int radio_mac_len,
	       const unsigned char *buf, ssize_t len)
{
	ei_x_buff x;

	/* prealloc enough space to hold the data plus the Erlang encoded meta data */
	ei_x_new_size(&x, 48 + len);
	ei_x_encode_version(&x);
	ei_x_encode_tuple_header(&x, 3);
	ei_x_encode_atom(&x, "capwap_in");
	ei_x_encode_sockaddr(&x, addr);
	/* hexdump(buf, len); */
	ei_x_encode_binary(&x, (void *)buf, len);

	control_enqueue(&x);
}

void dhcp_in(unsigned char *buf, ssize_t len)
{
	ei_x_buff x;

	/* prealloc enough space to hold the data plus the Erlang encoded meta data */
	ei_x_new_size(&x, 48 + len);
	ei_x_encode_version(&x);
	ei_x_encode_tuple_header(&x, 2);
	ei_x_encode_atom(&x, "dhcp_in");
	ei_x_encode_binary(&x, (void *)buf, len);

	control_enqueue(&x);
}

void packet_in_tap(uint16_t vlan, const unsigned char *buf, ssize_t len)
{
	ei_x_buff x;

	/* prealloc enough space to hold the data plus the Erlang encoded meta data */
	ei_x_new_size(&x, 48 + len);
	ei_x_encode_version(&x);
	ei_x_encode_tuple_header(&x, 4);
	ei_x_encode_atom(&x, "packet_in");
	ei_x_encode_atom(&x, "tap");
	ei_x_encode_ulong(&x, vlan);
	ei_x_encode_binary(&x, (void *)buf, len);

	control_enqueue(&x);
}

static void control_lock(EV_P)
{
	struct control_loop *c = ev_userdata (EV_A);
	pthread_mutex_lock(&c->loop_lock);
}

static void control_unlock(EV_P)
{
	struct control_loop *c = ev_userdata(EV_A);
	pthread_mutex_unlock (&c->loop_lock);
}

static int set_realtime_priority(void) {
	struct sched_param schp;

	/*
	 * set the process to realtime privs
	 */
	memset(&schp, 0, sizeof(schp));
	schp.sched_priority = sched_get_priority_max(SCHED_FIFO);

	if (sched_setscheduler(0, SCHED_FIFO, &schp) != 0) {
		perror("sched_setscheduler");
		return -1;
	}

	return 0;
}

int node_name_long = 0;
static char *node_name = NULL;
static char *cookie = "cookie";

static void dp_erl_connect(struct sockaddr_in *addr)
{
	char *p;
	char thishostname[EI_MAXHOSTNAMELEN];
	char thisalivename[EI_MAXHOSTNAMELEN];
	char thisnodename[EI_MAXHOSTNAMELEN];
	struct hostent *hp;

	strncpy(thisalivename, node_name, sizeof(thishostname));
	p = strchr(thisalivename, '@');
	if (p) {
		*p = '\0';
		strncpy(thishostname, p + 1, sizeof(thishostname));
		strncpy(thisnodename, node_name, sizeof(thishostname));
	} else {
		if (gethostname(thishostname, sizeof(thishostname)) < 0) {
			perror("gethostname");
			exit(EXIT_FAILURE);
		}

		if ((hp = gethostbyname(thishostname)) == 0) {
			/* Looking up IP given hostname fails. We must be on a standalone
			   host so let's use loopback for communication instead. */
			if ((hp = gethostbyname("localhost")) == 0) {
				perror("gethostbyname");
				exit(EXIT_FAILURE);
			}
		}

		log(LOG_DEBUG, "thishostname: %s, hp->h_name: '%s'", thishostname, hp->h_name);
		if (!node_name_long) {
			char* ct;
			if (strncmp(hp->h_name, "localhost", 9) == 0) {
				/* We use a short node name */
				if ((ct = strchr(thishostname, '.')) != NULL) *ct = '\0';
				snprintf(thisnodename, sizeof(thisnodename), "%s@%s", thisalivename, thishostname);
			} else {
				/* We use a short node name */
				if ((ct = strchr(hp->h_name, '.')) != NULL) *ct = '\0';
				strcpy(thishostname, hp->h_name);
				snprintf(thisnodename, sizeof(thisnodename), "%s@%s", thisalivename, hp->h_name);
			}
		} else
			snprintf(thisnodename, sizeof(thisnodename), "%s@%s", thisalivename, hp->h_name);
	}

	log(LOG_DEBUG, "thishostname:'%s'", thishostname);
	log(LOG_DEBUG, "thisalivename:'%s'", thisalivename);
	log(LOG_DEBUG, "thisnodename:'%s'", thisnodename);

	if (ei_connect_xinit(&ec, thishostname, thisalivename, thisnodename,
			     &addr->sin_addr, cookie, 0) < 0) {
		log(LOG_ERR, "ERROR when initializing: %d", erl_errno);
		exit(EXIT_FAILURE);
	}

	if (ei_publish(&ec, ntohs(addr->sin_port)) < 0) {
		log(LOG_ERR, "unable to register with EPMD: %d", erl_errno);
		exit(EXIT_FAILURE);
	}
}

static void usage(void)
{
	printf("Travelping CAPWAP Data Path Daemon\n\n"
	       "Usage: capwap-dp [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                                this help\n"
	       "  -V, --version                     show version information\n"
//               "  --dist=IP                         bind Erlang cluster protocol to interface\n"
	       "  --sname=NAME                      Erlang node short name\n"
	       "  -4, --v4only                      CAPWAP IPv4 only socket\n"
	       "  -6, --v6only                      CAPWAP IPv6 only socket\n"
	       "  -p, --port=PORT                   bind CAPWAP to PORT (default 5247)\n"
//               "  -i, --bind=BIND                   bind CAPWAP to IP\n"
	       "  -n, --netns=NAMESPACE             open CAPWAP socket in namespace\n"
	       "  -f, --forward-netns=NAMESPACE     create TAP interface in namespace\n"
	       "  --honor-df                        send ICMP notice based on IP DF bit\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

int v4only = 0;
int v6only = 0;
int capwap_port = 5247;
const char *capwap_ns = NULL;
const char *fwd_ns = NULL;
int honor_df = 0;

int unknown_wtp_limit_interval = 1000;
int unknown_wtp_limit_bucket = 30;

int main(int argc, char *argv[])
{
	const struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY
	};
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};

	int on = 1;
	int cfg_num_workers = 1;

	char *config_file = SYSCONFDIR "/capwap-dp.conf";

	config_t cfg;

	int c;
	socklen_t slen;

	/* unlimited size for cores */
	setrlimit(RLIMIT_CORE, &rlim);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"sname",         1, 0, 1024},
			{"name",          1, 0, 1025},
			{"honor-df",      1, 0, 1026},
			{"v4only",        0, 0, '4'},
			{"v6only",        0, 0, '6'},
			{"forward-netns", 1, 0, 'f'},
			{"netns",         1, 0, 'n'},
			{"port",          1, 0, 'p'},
			{"v4only",        0, 0, '4'},
			{"version",       0, 0, 'V'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "c:h46i:f:n:p:V",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			usage();
			break;

		case 1024:
			if (node_name) {
				fprintf(stderr, "--name and --sname can not be used together\n");
				exit(EXIT_FAILURE);
			}
			node_name = strdup(optarg);
			break;

		case 1025:
			if (node_name) {
				fprintf(stderr, "--name and --sname can not be used together\n");
				exit(EXIT_FAILURE);
			}
			node_name = strdup(optarg);
			node_name_long = 1;
			break;

		case 1026:
			honor_df = 1;
			break;

		case '4':
			if (v6only) {
				fprintf(stderr, "v4only and v6only can not be used together\n");
				exit(EXIT_FAILURE);
			}
			v4only = 1;
			break;

		case '6':
			if (v4only) {
				fprintf(stderr, "v4only and v6only can not be used together\n");
				exit(EXIT_FAILURE);
			}
			v6only = 1;
			break;

		case 'V':
			printf("%s\n", VERSION);
			exit(0);

		case 'c':
			config_file = strdup(optarg);
			break;
/*
		case 'i':
			if (inet_aton(optarg, &addr.sin_addr) == 0) {
				fprintf(stderr, "Invalid IP address: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
*/

		case 'f':
			fwd_ns = strdup(optarg);
			break;

		case 'n':
			capwap_ns = strdup(optarg);
			break;

		case 'p':
			capwap_port = strtol(optarg, NULL, 0);
			if (errno != 0) {
				fprintf(stderr, "Invalid numeric argument: '%s'\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;

		default:
			printf("invalid option -- '%c'\n", c);
			exit(EXIT_FAILURE);
		}
	}

	config_init(&cfg);

	if (access(config_file, R_OK) == 0) {
		/* Read the file. If there is an error, report it and exit. */
		if (!config_read_file(&cfg, config_file)) {
			fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
				config_error_line(&cfg), config_error_text(&cfg));
			config_destroy(&cfg);
			return(EXIT_FAILURE);
		}

		config_lookup_string(&cfg, "node.name", (const char **)&node_name);
		config_lookup_string(&cfg, "node.cookie", (const char **)&cookie);

		config_lookup_int(&cfg, "capwap.listen.port", &capwap_port);
		config_lookup_string(&cfg, "capwap.listen.namespace", &capwap_ns);
		config_lookup_string(&cfg, "capwap.forward.namespace", &fwd_ns);
		config_lookup_bool(&cfg, "capwap.forward.honor-df-bit", &honor_df);

		config_lookup_int(&cfg, "capwap.ratelimit.unknown-wtp.interval", &unknown_wtp_limit_interval);
		config_lookup_int(&cfg, "capwap.ratelimit.unknown-wtp.bucket", &unknown_wtp_limit_bucket);

		config_lookup_int(&cfg, "capwap.workers", &cfg_num_workers);
	} else {
		fprintf(stderr, "can't open config file %s, running with default config\n", config_file);
		log(LOG_WARNING, "can't open config file %s, running with default config", config_file);
	}

	if (!node_name)
		node_name = strdup("capwap-dp");

	if (mlockall(MCL_CURRENT|MCL_FUTURE))
		perror("mlockall() failed");

	if (set_realtime_priority() < 0) {
		fprintf(stderr, "can't get realtime priority, run capwap-dp as root.\n");
		log(LOG_WARNING, "can't get realtime priority, run capwap-dp as root.");
	}

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	pthread_mutex_init(&ctrl.loop_lock, 0);

	ctrl.loop = EV_DEFAULT;
	cds_lfq_init_rcu(&ctrl.queue, call_rcu);

	// now associate this with the loop
	ev_set_userdata(ctrl.loop, &ctrl);
	ev_set_loop_release_cb(ctrl.loop, control_unlock, control_lock);

	ev_async_init(&ctrl.q_ev, q_cb);
	ev_async_start(ctrl.loop, &ctrl.q_ev);

	init_netns();

	if ((ctrl.listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0)
		exit(EXIT_FAILURE);

	setsockopt(ctrl.listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(ctrl.listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("error bind: %m\n");
		exit(EXIT_FAILURE);
	}

	slen = sizeof(addr);
	if (getsockname(ctrl.listen_fd, (struct sockaddr *)&addr, &slen) < 0) {
		printf("error getsockname: %m\n");
		exit(EXIT_FAILURE);
	}

	dp_erl_connect(&addr);

	listen(ctrl.listen_fd, 5);

	ev_io_init(&ctrl.control_ev, control_cb, ctrl.listen_fd, EV_READ);
	ev_io_start(ctrl.loop, &ctrl.control_ev);

	start_worker(cfg_num_workers);

#ifdef USE_SYSTEMD_DAEMON
	/* Subsequent notifications will be ignored by systemd
	 * and calling this function will clean up the env */
	if (sd_notify(0, "READY=1") <= 0) {
		log(LOG_INFO, "starting loop");
	}
#else
	log(LOG_INFO, "starting loop");
#endif

	control_lock(ctrl.loop);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	ev_run(ctrl.loop, 0);
	control_unlock(ctrl.loop);

	return 0;
}
