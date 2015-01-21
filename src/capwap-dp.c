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
#include <arpa/inet.h>
#include <getopt.h>

#include <urcu.h>               /* RCU flavor */
#include <urcu/uatomic.h>
#include <urcu/ref.h>		/* ref counting */
#include <urcu/rculist.h>       /* RCU list */
#include <urcu/rculfqueue.h>    /* RCU Lock-free queue */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include "jhash.h"

#include <libconfig.h>

#include <ev.h>

#ifdef USE_SYSTEMD_DAEMON
#include <systemd/sd-daemon.h>
#endif

#include "erl_interface.h"
#include "ei.h"

#include "log.h"
#include "capwap-dp.h"
#include "netns.h"

static const char _ident[] = "capwap-dp v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct control_loop {
	struct ev_loop *loop;
	pthread_mutex_t loop_lock; /* global loop lock */

	int listen_fd;
	ev_io control_ev;

	struct cds_lfq_queue_rcu queue;
	ev_async q_ev;
};

static struct control_loop ctrl;

struct controller {
	struct rcu_head rcu_head;       /* For call_rcu() */
	struct cds_list_head controllers;

	int fd;
	ErlConnect conp;

	ev_io ev_read;
	// write_lock

	ETERM *bind_pid;
};

CDS_LIST_HEAD(controllers);
static ei_cnode ec;

static int ipv4sockaddr(ETERM *ip, unsigned int port, struct sockaddr_in *addr)
{
	uint32_t a = 0;

	for (int i = 0; i < 4; i++) {
		ETERM *n = erl_element(i+1, ip);
		a = a << 8;
		a |= ERL_INT_UVALUE(n);
		erl_free_term(n);
	}

	addr->sin_family = AF_INET;
	addr->sin_port = htons(port);
	addr->sin_addr.s_addr = htonl(a);

	return 1;
}

static int ipv6_v4mappedsockaddr(ETERM *ip, unsigned int port, struct sockaddr_in6 *addr)
{
	uint32_t a = 0;

	for (int i = 0; i < 4; i++) {
		ETERM *n = erl_element(i+1, ip);
		a = a << 8;
		a |= ERL_INT_UVALUE(n);
		erl_free_term(n);
	}

	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(port);
	addr->sin6_addr.s6_addr32[0] = 0;
	addr->sin6_addr.s6_addr32[1] = 0;
	addr->sin6_addr.s6_addr32[2] = htonl(0xffff);
	addr->sin6_addr.s6_addr32[3] = htonl(a);

	return 1;
}

static int ipv6sockaddr(ETERM *ip, unsigned int port, struct sockaddr_in6 *addr)
{
	addr->sin6_family = AF_INET6;
	addr->sin6_port = htons(port);

	for (int i = 0; i < 8; i++) {
		ETERM *n = erl_element(i+1, ip);
		addr->sin6_addr.s6_addr16[i] = htons(ERL_INT_UVALUE(n));
		erl_free_term(n);
	}

	return 1;
}

static int tuple2sockaddr(ETERM *ea, struct sockaddr_storage *addr)
{
	ETERM *ip, *port;
	int res = 0;

	if (ERL_TUPLE_SIZE(ea) != 2)
		goto out;

	ip = erl_element(1, ea);
	port = erl_element(2, ea);

	memset(addr, 0, sizeof(struct sockaddr_storage));

	if (ERL_IS_INTEGER(port))
		switch (ERL_TUPLE_SIZE(ip)) {
		case 4:
			if (!v4only)
				res = ipv6_v4mappedsockaddr(ip, ERL_INT_UVALUE(port), (struct sockaddr_in6 *)addr);
			else
				res = ipv4sockaddr(ip, ERL_INT_UVALUE(port), (struct sockaddr_in *)addr);
			break;

		case 8:
			res = ipv6sockaddr(ip, ERL_INT_UVALUE(port), (struct sockaddr_in6 *)addr);
			break;
		}

	erl_free_term(ip);
	erl_free_term(port);

out:
	erl_free_term(ea);
	return res;
}

static void free_erl_term_array(ETERM **arr, int count)
{
	while (count > 0) {
		erl_free_term(*arr);

		arr++;
		count--;
	}
}

static ETERM *erl_term_array_to_tuple(ETERM **arr, int count)
{
	ETERM *ret;

	ret = erl_mk_tuple(arr, count);
	free_erl_term_array(arr, count);

	return ret;
}

static ETERM *erl_list_append(ETERM *hd, ETERM *tl)
{
	ETERM *ret;

	ret = erl_cons(hd, tl);
	erl_free_term(tl);
	erl_free_term(hd);

	return ret;
}

static ETERM *sockaddr2term(const struct sockaddr *addr)
{
	char ipaddr[INET6_ADDRSTRLEN];
	ETERM *eaddr[2];

	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(addr)));

	switch (addr->sa_family) {
	case AF_INET: {
		ETERM *ip[4];
		struct sockaddr_in *in = (struct sockaddr_in *)addr;
		uint8_t *a = (uint8_t *)&in->sin_addr.s_addr;

		for (int i = 0; i < 4; i++)
			ip[i] = erl_mk_int(a[i]);
		eaddr[0] = erl_term_array_to_tuple(ip, 4);
		eaddr[1] = erl_mk_int(ntohs(in->sin_port));

		break;
	}

	case AF_INET6: {
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

		if (IN6_IS_ADDR_V4MAPPED(&in6->sin6_addr)) {
			uint8_t *a = (uint8_t *)&in6->sin6_addr.s6_addr32[3];
			ETERM *ip[4];

			for (int i = 0; i < 4; i++)
				ip[i] = erl_mk_int(a[i]);
			eaddr[0] = erl_term_array_to_tuple(ip, 4);
		} else {
			ETERM *ip[8];

			for (int i = 0; i < 8; i++)
				ip[i] = erl_mk_int(ntohs(in6->sin6_addr.s6_addr16[i]));
			eaddr[0] = erl_term_array_to_tuple(ip, 8);
		}
		eaddr[1] = erl_mk_int(ntohs(in6->sin6_port));

		break;
	}
	}

	return erl_term_array_to_tuple(eaddr, 2);
}

static int bin2ether(ETERM *ea, uint8_t *ether)
{
	int res = 0;

	if (!ERL_IS_BINARY(ea) || (ERL_BIN_SIZE(ea) != ETH_ALEN))
		goto out;

	memcpy(ether, ERL_BIN_PTR(ea), ETH_ALEN);
	res = 1;

out:
	erl_free_term(ea);
	return res;
}

static ETERM *ether2bin(uint8_t *ether)
{
	return erl_mk_binary((char *)ether, ETH_ALEN);
}

static ETERM *sta2term(struct station *sta)
{
	ETERM *esta[2];
	ETERM *esta_cnt[] = {
		erl_mk_longlong(uatomic_read(&sta->rcvd_pkts)),
		erl_mk_longlong(uatomic_read(&sta->send_pkts)),
		erl_mk_longlong(uatomic_read(&sta->rcvd_bytes)),
		erl_mk_longlong(uatomic_read(&sta->send_bytes))
	};

	esta[0] = ether2bin(sta->ether);
	esta[1] = erl_term_array_to_tuple(esta_cnt, CAA_ARRAY_SIZE(esta_cnt));

	return erl_term_array_to_tuple(esta, CAA_ARRAY_SIZE(esta));
}

static ETERM *wtp2term(struct client *clnt)
{
	struct station *sta;
	ETERM *wtp[5];
	ETERM *wtp_cnt[] = {
		erl_mk_longlong(uatomic_read(&clnt->rcvd_pkts)),
		erl_mk_longlong(uatomic_read(&clnt->send_pkts)),
		erl_mk_longlong(uatomic_read(&clnt->rcvd_bytes)),
		erl_mk_longlong(uatomic_read(&clnt->send_bytes)),

		erl_mk_longlong(uatomic_read(&clnt->rcvd_fragments)),
		erl_mk_longlong(uatomic_read(&clnt->send_fragments)),

		erl_mk_longlong(uatomic_read(&clnt->err_invalid_station)),
		erl_mk_longlong(uatomic_read(&clnt->err_fragment_invalid)),
		erl_mk_longlong(uatomic_read(&clnt->err_fragment_too_old))
	};

	wtp[0] = sockaddr2term((struct sockaddr *)&clnt->addr);
	wtp[1] = erl_mk_empty_list();
	wtp[2] = erl_mk_int(clnt->ref.refcount);
	wtp[3] = erl_mk_int(clnt->mtu);
	wtp[4] = erl_term_array_to_tuple(wtp_cnt, CAA_ARRAY_SIZE(wtp_cnt));

	cds_hlist_for_each_entry_rcu_2(sta, &clnt->stations, wtp_list) {
		wtp[1] = erl_list_append(sta2term(sta), wtp[1]);
	}

	return erl_term_array_to_tuple(wtp, CAA_ARRAY_SIZE(wtp));
}

static void async_reply(struct controller *cnt, ETERM *from, ETERM *resp)
{
	ETERM *pid, *m;
	ETERM *marr[2];

	pid = erl_element(1, from);

	/* M = {Tag, Msg} */
	marr[0] = erl_element(2, from);  /* Tag */
	marr[1] = erl_copy_term(resp);
	m = erl_term_array_to_tuple(marr, 2);

	erl_send(cnt->fd, pid, m);

	erl_free_term(pid);
	erl_free_term(m);
}

static void cnt_send(struct controller *cnt, ETERM *term)
{
	if (cnt->bind_pid)
		erl_send(cnt->fd, cnt->bind_pid, term);
}

static ETERM *erl_bind(struct controller *cnt, ETERM *tuple)
{
	ETERM *pid;

	if (cnt->bind_pid) {
		erl_free_term(cnt->bind_pid);
		cnt->bind_pid = NULL;
	}

	pid = erl_element(2, tuple);
	if (ERL_IS_PID(pid))
		cnt->bind_pid = erl_copy_term(pid);

	erl_free_term(pid);

	return erl_mk_atom("ok");
}

static ETERM *erl_send_to(ETERM *tuple)
{
	ETERM *msg;
	ssize_t r;
	struct client *clnt;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;

	if (ERL_TUPLE_SIZE(tuple) != 3)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr))
		return erl_mk_atom("badarg");

	inet_ntop(addr.ss_family, SIN_ADDR_PTR(&addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&addr)));

	msg = erl_element(3, tuple);
	if (!ERL_IS_BINARY(msg)) {
		erl_free_term(msg);
		return erl_mk_atom("badarg");
	}

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) != NULL) {
		/* FIXME: queue request to WTP */

		inet_ntop(clnt->addr.ss_family, SIN_ADDR_PTR(&clnt->addr), ipaddr, sizeof(ipaddr));
		fprintf(stderr, "Client IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&clnt->addr)));

		assert(memcmp(&addr, &clnt->addr, clnt->addr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == 0);

		r = sendto(workers[0].capwap_fd, ERL_BIN_PTR(msg), ERL_BIN_SIZE(msg),
			   0, (struct sockaddr *)&clnt->addr, sizeof(clnt->addr));
		fprintf(stderr, "erl_send_to: %zd\n", r);
	} else
		fprintf(stderr, "failed to find client: %p\n", clnt);

	rcu_read_unlock();

	erl_free_term(msg);

	return erl_mk_atom("ok");
}

static ETERM *erl_add_wtp(ETERM *tuple)
{
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;
	ETERM *emtu;
	unsigned int mtu;

	if (ERL_TUPLE_SIZE(tuple) != 3)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr))
		return erl_mk_atom("badarg");

	inet_ntop(addr.ss_family, SIN_ADDR_PTR(&addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&addr)));

	emtu = erl_element(3, tuple);
	if (!ERL_IS_INTEGER(emtu)) {
		erl_free_term(emtu);
		return erl_mk_atom("badarg");
	}
	mtu = ERL_INT_UVALUE(emtu);
	erl_free_term(emtu);

	if (!add_wtp((struct sockaddr *)&addr, mtu))
		return erl_mk_atom("enomem");

	return erl_mk_atom("ok");
}

static ETERM *erl_get_wtp(ETERM *tuple)
{
	ETERM *res;
	struct client *clnt;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;

	if (ERL_TUPLE_SIZE(tuple) != 2)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr))
		return erl_mk_atom("badarg");

	inet_ntop(addr.ss_family, SIN_ADDR_PTR(&addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&addr)));

	rcu_read_lock();

	if ((clnt = find_wtp((struct sockaddr *)&addr)) != NULL) {
		res = wtp2term(clnt);
	} else
		res = erl_mk_atom("not_found");

	rcu_read_unlock();

	return res;
}

static ETERM *erl_del_wtp(ETERM *tuple)
{
	int r;
	struct sockaddr_storage addr;

	if (ERL_TUPLE_SIZE(tuple) != 2)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr))
		return erl_mk_atom("badarg");

	r = delete_wtp((struct sockaddr *)&addr);
	return (r ? erl_mk_atom("ok") : erl_mk_atom("failed"));
}

static ETERM *erl_list_wtp(ETERM *tuple)
{
	ETERM *list;

	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *clnt;

	list = erl_mk_empty_list();

	rcu_read_lock();
	cds_lfht_for_each_entry(ht_clients, &iter, clnt, node) {
		list = erl_list_append(wtp2term(clnt), list);
	}
	rcu_read_unlock();

	return list;
}

static ETERM *erl_list_stations(ETERM *tuple)
{
	ETERM *list;

	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct station *sta;

	list = erl_mk_empty_list();

	rcu_read_lock();
        cds_lfht_for_each_entry(ht_stations, &iter, sta, station_hash) {
		list = erl_list_append(sta2term(sta), list);
	}
	rcu_read_unlock();

	return list;
}

static ETERM *erl_clear()
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *wtp;

	rcu_read_lock();

	cds_lfht_for_each_entry(ht_clients, &iter, wtp, node)
		__delete_wtp(wtp);

	rcu_read_unlock();

	return erl_mk_atom("ok");
}

static ETERM *erl_attach_station(ETERM *tuple)
{
	struct station *sta;
	struct client *clnt;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;
	uint8_t ether[ETH_ALEN];
	ETERM *res;

	unsigned long hash;

	if (ERL_TUPLE_SIZE(tuple) != 3)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr)
	    || !bin2ether(erl_element(3, tuple), ether))
		return erl_mk_atom("badarg");

	inet_ntop(addr.ss_family, SIN_ADDR_PTR(&addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&addr)));
	fprintf(stderr, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ether[0], ether[1], ether[2], ether[3], ether[4], ether[5]);

	rcu_read_lock();

	if (find_station(ether) != NULL) {
		res = erl_mk_atom("duplicate");
		goto out_unlock;
	}

	if ((clnt = find_wtp((struct sockaddr *)&addr)) == NULL) {
		res = erl_mk_atom("not_found");
		goto out_unlock;
	}

	hash = jhash(ether, ETH_ALEN, 0x12345678);

	sta = calloc(1, sizeof(struct station));
	if (!sta)
		return erl_mk_atom("enomem");

	urcu_ref_init(&sta->ref);
	cds_lfht_node_init(&sta->station_hash);
	memcpy(&sta->ether, &ether, sizeof(ether));

	/*
	 * Mutating operations need mutal exclusion from each other,
	 * only concurrent reads are allowed.
	 * This is currently guaranteed since only the
	 * control thread is permitted to call this.
	 */
	cds_lfht_add(ht_stations, hash, &sta->station_hash);
	attach_station_to_wtp(clnt, sta);

	res = erl_mk_atom("ok");

out_unlock:
	rcu_read_unlock();

	return res;
}

static ETERM *erl_detach_station(ETERM *tuple)
{
	struct station *sta;
	uint8_t ether[ETH_ALEN];
	ETERM *res;

	if (ERL_TUPLE_SIZE(tuple) != 2)
		return erl_mk_atom("badarg");

	if (!bin2ether(erl_element(2, tuple), ether))
		return erl_mk_atom("badarg");

	fprintf(stderr, "MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ether[0], ether[1], ether[2], ether[3], ether[4], ether[5]);

	rcu_read_lock();

	if ((sta = find_station(ether)) != NULL) {
		if (cds_lfht_del(ht_stations, &sta->station_hash) == 0) {
			detach_station_from_wtp(sta);
			res = erl_mk_atom("ok");
		} else {
			log(LOG_ALERT, "station hash corrupt");
			res = erl_mk_atom("hash_corrupt");
		}
	} else
		res = erl_mk_atom("not_found");

	rcu_read_unlock();

	return res;
}

static ETERM *erl_get_stats()
{
	ETERM *res;

	res = erl_mk_empty_list();
	for (int i = 0; i < num_workers; i++) {
		ETERM *w[] = {
			erl_mk_longlong(uatomic_read(&workers[i].rcvd_pkts)),
			erl_mk_longlong(uatomic_read(&workers[i].send_pkts)),
			erl_mk_longlong(uatomic_read(&workers[i].rcvd_bytes)),
			erl_mk_longlong(uatomic_read(&workers[i].send_bytes)),

			erl_mk_longlong(uatomic_read(&workers[i].rcvd_fragments)),
			erl_mk_longlong(uatomic_read(&workers[i].send_fragments)),

			erl_mk_longlong(uatomic_read(&workers[i].err_invalid_station)),
			erl_mk_longlong(uatomic_read(&workers[i].err_fragment_invalid)),
			erl_mk_longlong(uatomic_read(&workers[i].err_fragment_too_old)),

			erl_mk_longlong(uatomic_read(&workers[i].err_invalid_wtp)),
			erl_mk_longlong(uatomic_read(&workers[i].err_hdr_length_invalid)),
			erl_mk_longlong(uatomic_read(&workers[i].err_too_short)),
			erl_mk_longlong(uatomic_read(&workers[i].ratelimit_unknown_wtp))
		};

		res = erl_list_append(erl_term_array_to_tuple(w, CAA_ARRAY_SIZE(w)), res);
	}
	return res;
}
static ETERM *handle_gen_call_capwap(struct controller *cnt, const char *fn, ETERM *tuple)
{
	if (strncmp(fn, "sendto", 6) == 0) {
		return erl_send_to(tuple);
	}
	if (strncmp(fn, "bind", 4) == 0) {
		return erl_bind(cnt, tuple);
	}
	if (strncmp(fn, "clear", 4) == 0) {
		return erl_clear();
	}
	if (strncmp(fn, "add_wtp", 7) == 0) {
		return erl_add_wtp(tuple);
	}
	else if (strncmp(fn, "del_wtp", 7) == 0) {
		return erl_del_wtp(tuple);
	}
	else if (strncmp(fn, "list_wtp", 8) == 0) {
		return erl_list_wtp(tuple);
	}
	else if (strncmp(fn, "get_wtp", 7) == 0) {
		return erl_get_wtp(tuple);
	}
	else if (strncmp(fn, "attach_station", 14) == 0) {
		return erl_attach_station(tuple);
	}
	else if (strncmp(fn, "detach_station", 14) == 0) {
		return erl_detach_station(tuple);
	}
	else if (strncmp(fn, "list_stations", 13) == 0) {
		return erl_list_stations(tuple);
	}
	else if (strncmp(fn, "get_stats", 9) == 0) {
		return erl_get_stats(tuple);
	}
	else
		return erl_mk_atom("error");
}

static void handle_gen_call(struct controller *cnt, const char *to, ETERM *from, ETERM *tuple)
{
	ETERM *fn;
	ETERM *resp;

	fn = erl_element(1, tuple);

	if (strncmp(to, "net_kernel", 10) == 0 &&
	    strncmp(ERL_ATOM_PTR(fn), "is_auth", 7) == 0) {
		resp = erl_mk_atom("yes");
	}
	else if (strncmp(to, "capwap", 6) == 0) {
		resp = handle_gen_call_capwap(cnt, ERL_ATOM_PTR(fn), tuple);
	}
	else
		resp = erl_mk_atom("error");

	async_reply(cnt, from, resp);

	erl_free_term(fn);
	erl_free_term(resp);
}

static void handle_gen_cast(struct controller *cnt, ETERM *cast)
{
}

static void erl_read_cb(EV_P_ ev_io *w, int revents)
{
	ei_x_buff x;
	erlang_msg msg;
	int r;

	ei_x_new(&x);
	r = ei_xreceive_msg(w->fd, &msg, &x);
	if (r == ERL_TICK) {
		/* ignore */
	} else if (r == ERL_ERROR) {
		fprintf(stderr, "ERROR on fd %d, %s (%d)\n", w->fd, strerror(erl_errno), erl_errno);
		close(w->fd);
		ev_io_stop (EV_A_ w);
	} else {
		struct controller *cnt = caa_container_of(w, struct controller, ev_read);
		int index = 0;

		switch (msg.msgtype) {
		case ERL_REG_SEND: {
			ETERM *fmsg, *type;

			ei_decode_term(x.buff, &index, &fmsg);
			type = erl_element(1, fmsg);

			fprintf(stderr, "Msg to: %s, ", msg.toname);
			erl_print_term(stderr, fmsg);
			fprintf(stderr, "\n");

			if (strncmp(ERL_ATOM_PTR(type), "$gen_call", 9) == 0) {
				ETERM *from, *call;

				from = erl_element(2, fmsg);
				call = erl_element(3, fmsg);
				handle_gen_call(cnt, msg.toname, from, call);
				erl_free_term(from);
				erl_free_term(call);
			}
			else if (strncmp(ERL_ATOM_PTR(type), "$gen_cast", 9) == 0) {
				ETERM *cast;

				cast = erl_element(2, fmsg);
				handle_gen_cast(cnt, cast);
				erl_free_term(cast);
			}

			erl_free_term(type);
			erl_free_term(fmsg);

			break;
		}
		default:
			fprintf(stderr, "msg.msgtype: %ld\n", msg.msgtype);
			break;
		}
	}

	ei_x_free(&x);
}

static void control_cb(EV_P_ ev_io *w, int revents)
{
	struct controller *cnt;

	if (!(cnt = malloc(sizeof(struct controller))))
		return;
	memset(cnt, 0, sizeof(struct controller));

	if ((cnt->fd = ei_accept_tmo(&ec, w->fd, &cnt->conp, 100)) == ERL_ERROR) {
		fprintf(stderr, "Failed to ei_accept on fd %d with %s (%d)\n", w->fd, strerror(erl_errno), erl_errno);
		free(cnt);
		return;
	}

	fprintf(stderr, "ei_accept, got fd %d (%d)\n", cnt->fd, erl_errno);

	ev_io_init(&cnt->ev_read, erl_read_cb, cnt->fd, EV_READ);
	ev_io_start(EV_A_ &cnt->ev_read);

	cds_list_add_rcu(&cnt->controllers, &controllers);
}

struct cq_node {
	ETERM *term;

	struct cds_lfq_node_rcu node;
	struct rcu_head rcu_head;       /* For call_rcu() */
};

static void free_qnode(struct rcu_head *head)
{
	struct cq_node *node = caa_container_of(head, struct cq_node, rcu_head);

	erl_free_term(node->term);
	free(node);
}

static void control_enqueue(ETERM *term)
{
	struct cq_node *cq;

	cq = calloc(1, sizeof(struct cq_node));
	if (!cq)
		return;

	cds_lfq_node_init_rcu(&cq->node);
	cq->term = term;

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
			cnt_send(cnt, cq->term);
		}

		call_rcu(&cq->rcu_head, free_qnode);
	}
}

void capwap_socket_error(int origin, int type, const struct sockaddr *addr)
{
	ETERM *msg[4];

	msg[0] = erl_mk_atom("capwap_error");
	msg[1] = erl_mk_int(origin);
	msg[2] = erl_mk_int(type);
	msg[3] = sockaddr2term(addr);

	control_enqueue(erl_term_array_to_tuple(msg, 4));
}

void capwap_in(const struct sockaddr *addr,
	       const unsigned char *radio_mac, unsigned int radio_mac_len,
	       const unsigned char *buf, ssize_t len)
{
	ETERM *msg[3];

	msg[0] = erl_mk_atom("capwap_in");
	msg[1] = sockaddr2term(addr);
	msg[2] = erl_mk_binary((char *)buf, len);

	control_enqueue(erl_term_array_to_tuple(msg, 3));
}

void packet_in_tap(const unsigned char *buf, ssize_t len)
{
	ETERM *msg[3];

	msg[0] = erl_mk_atom("packet_in");
	msg[1] = erl_mk_atom("tap");
	msg[2] = erl_mk_binary((char *)buf, len);

	control_enqueue(erl_term_array_to_tuple(msg, 3));
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

		fprintf(stderr, "thishostname: %s, hp->h_name: '%s'\n", thishostname, hp->h_name);
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

	fprintf(stderr, "thishostname:'%s'\n", thishostname);
	fprintf(stderr, "thisalivename:'%s'\n", thisalivename);
	fprintf(stderr, "thisnodename:'%s'\n", thisnodename);

	if (ei_connect_xinit(&ec, thishostname, thisalivename, thisnodename,
			     &addr->sin_addr, cookie, 0) < 0) {
		fprintf(stderr,"ERROR when initializing: %d",erl_errno);
		exit(EXIT_FAILURE);
	}

	if (ei_publish(&ec, ntohs(addr->sin_port)) < 0) {
		fprintf(stderr,"unable to register with EPMD: %d", erl_errno);
		exit(EXIT_FAILURE);
	}
}

static void usage(void)
{
	printf("TPLINO CAPWAP Data Path Deamon, Version: .....\n\n"
	       "Usage: capwap-dp [OPTION...]\n\n"
	       "Options:\n\n"
	       "  -h                                this help\n"
//               "  --dist=IP                         bind Erlang cluster protocol to interface\n"
	       "  --sname=NAME                      Erlang node short name\n"
	       "  -4, --v4only                      CAPWAP IPv4 only socket\n"
	       "  -6, --v6only                      CAPWAP IPv6 only socket\n"
	       "  -p, --port=PORT                   bind CAPWAP to PORT (default 5247)\n"
//               "  -i, --bind=BIND                   bind CAPWAP to IP\n"
	       "  -n, --netns=NAMESPACE             open CAPWAP socket in namespace\n"
	       "  -f, --forward-netns=NAMESPACE     create TAP interface in namespace\n"
	       "\n");

	exit(EXIT_SUCCESS);
}

int v4only = 0;
int v6only = 0;
int capwap_port = 5247;
const char *capwap_ns = NULL;
const char *fwd_ns = NULL;

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
	int cfg_num_workers = 8;

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
			{"name",         1, 0, 1025},
			{"v4only",        0, 0, '4'},
			{"v6only",        0, 0, '6'},
			{"forward-netns", 1, 0, 'f'},
			{"netns",         1, 0, 'n'},
			{"port",          1, 0, 'p'},
			{"v4only",        0, 0, '4'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "c:h46i:f:n:p:",
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
			printf("?? getopt returned character code 0%o ??\n", c);
		}
	}

	config_init(&cfg);

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

	config_lookup_int(&cfg, "capwap.ratelimit.unknown-wtp.interval", &unknown_wtp_limit_interval);
	config_lookup_int(&cfg, "capwap.ratelimit.unknown-wtp.bucket", &unknown_wtp_limit_bucket);

	config_lookup_int(&cfg, "capwap.workers", &cfg_num_workers);

	if (!node_name)
		node_name = strdup("capwap-dp");

	if (mlockall(MCL_CURRENT|MCL_FUTURE))
		perror("mlockall() failed");

	if (set_realtime_priority() < 0)
		fprintf(stderr, "can't get realtime priority, run capwap-dp as root.\n");

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
	erl_init(NULL, 0);

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
