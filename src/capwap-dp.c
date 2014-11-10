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
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <getopt.h>

#include <urcu.h>               /* RCU flavor */
#include <urcu/ref.h>		/* ref counting */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include "jhash.h"

#include <ev.h>

#include "erl_interface.h"
#include "ei.h"

#include "capwap-dp.h"
#include "netns.h"

static const char _ident[] = "capwap-dp v" VERSION;
static const char _build[] = "build on " __DATE__ " " __TIME__ " with gcc " __VERSION__;

struct controller {
	LIST_ENTRY(controller) controllers;

	int fd;
	ErlConnect conp;

	ev_io ev_read;
	// write_lock
};

LIST_HEAD(controllers, controller) controllers = LIST_HEAD_INITIALIZER(controllers);
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

	if (ERL_IS_INTEGER(port))
		switch (ERL_TUPLE_SIZE(ip)) {
		case 4:
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

ETERM *sockaddr2term(struct sockaddr *addr)
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

		eaddr[0] = erl_mk_tuple(ip, 4);
		eaddr[1] = erl_mk_int(ntohs(in->sin_port));

		break;
	}
	case AF_INET6: {
		ETERM *ip[8];
		struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)addr;

		for (int i = 0; i < 8; i++)
			ip[i] = erl_mk_int(ntohs(in6->sin6_addr.s6_addr16[i]));

		eaddr[0] = erl_mk_tuple(ip, 8);
		eaddr[1] = erl_mk_int(ntohs(in6->sin6_port));

		break;
	}
	}

	return erl_mk_tuple(eaddr, 2);
}

int bin2ether(ETERM *ea, uint8_t *ether)
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

ETERM *ether2bin(uint8_t *ether)
{
	return erl_mk_binary((char *)ether, ETH_ALEN);
}

ETERM *wtp2term(struct client *clnt)
{
	struct station *sta;
	ETERM *wtp[3];

	wtp[0] = sockaddr2term((struct sockaddr *)&clnt->addr);
	wtp[1] = erl_mk_empty_list();
	wtp[2] = erl_mk_int(clnt->ref.refcount);

        cds_hlist_for_each_entry_rcu_2(sta, &clnt->stations, wtp_list) {
		ETERM *mac = ether2bin(sta->ether);
		wtp[1] = erl_cons(mac, wtp[1]);
	}

	return erl_mk_tuple(wtp, 3);
}

static void async_reply(int fd, ETERM *from, ETERM *resp)
{
	ETERM *pid, *m;
	ETERM *marr[2];

	pid = erl_element(1, from);

	/* M = {Tag, Msg} */
	marr[0] = erl_element(2, from);  /* Tag */
	marr[1] = resp;
	m = erl_mk_tuple(marr, 2);

	erl_send(fd, pid, m);
}

static ETERM *erl_send_to(ETERM *tuple)
{
	ETERM *res, *msg;
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

		r = sendto(workers[0].capwap_fd, ERL_BIN_PTR(msg), ERL_BIN_SIZE(msg),
			   0, (struct sockaddr *)&clnt->addr, sizeof(clnt->addr));
		fprintf(stderr, "erl_send_to: %zd\n", r);
	}

	rcu_read_unlock();

	erl_free_term(msg);

	return erl_mk_atom("ok");
}

static ETERM *erl_add_wtp(ETERM *tuple)
{
	struct client *clnt;
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr_storage addr;

	unsigned long hash;

	if (ERL_TUPLE_SIZE(tuple) != 2)
		return erl_mk_atom("badarg");

	if (!tuple2sockaddr(erl_element(2, tuple), &addr))
		return erl_mk_atom("badarg");

	inet_ntop(addr.ss_family, SIN_ADDR_PTR(&addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "IP: %s:%d\n", ipaddr, ntohs(SIN_PORT(&addr)));

	hash = hash_sockaddr((struct sockaddr *)&addr);

	clnt = calloc(1, sizeof(struct client));
	if (!clnt)
		return erl_mk_atom("enomem");

	urcu_ref_init(&clnt->ref);
	cds_lfht_node_init(&clnt->node);
	CDS_INIT_HLIST_HEAD(&clnt->stations);
	memcpy(&clnt->addr, &addr, sizeof(addr));

	/*
	 * cds_lfht_add() needs to be called from RCU read-side
	 * critical section.
	 */
	rcu_read_lock();
	cds_lfht_add(ht_clients, hash, &clnt->node);
	rcu_read_unlock();

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
	return erl_mk_atom("not implemented yet");
}

static ETERM *erl_list_wtp(ETERM *tuple)
{
	ETERM *list;

        struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *clnt;

	list = erl_mk_empty_list();

        rcu_read_lock();
        cds_lfht_for_each_entry(ht_clients, &iter, clnt, node) {
		ETERM *ip = sockaddr2term((struct sockaddr *)&clnt->addr);
		list = erl_cons(ip, list);
        }
        rcu_read_unlock();

	return list;
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
		detach_station_from_wtp(sta);
		res = erl_mk_atom("ok");
	} else
		res = erl_mk_atom("not_found");

	rcu_read_unlock();

	return res;
}

static ETERM *handle_gen_call_capwap(const char *fn, ETERM *tuple)
{
	if (strncmp(fn, "sendto", 6) == 0) {
		return erl_send_to(tuple);
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
	else
		return erl_mk_atom("error");
}

static void handle_gen_call(int fd, const char *to, ETERM *from, ETERM *tuple)
{
	ETERM *fn;
	ETERM *resp;

	fn = erl_element(1, tuple);

	if (strncmp(to, "net_kernel", 10) == 0 &&
	    strncmp(ERL_ATOM_PTR(fn), "is_auth", 7) == 0) {
		resp = erl_mk_atom("yes");
	}
	else if (strncmp(to, "capwap", 6) == 0) {
		resp = handle_gen_call_capwap(ERL_ATOM_PTR(fn), tuple);
	}
	else
		resp = erl_mk_atom("error");

	async_reply(fd, from, resp);

	erl_free_term(fn);
	erl_free_term(resp);
}

static void handle_gen_cast(int fd, ETERM *cast)
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
				handle_gen_call(w->fd, msg.toname, from, call);
				erl_free_term(from);
				erl_free_term(call);
			}
			else if (strncmp(ERL_ATOM_PTR(type), "$gen_cast", 9) == 0) {
				ETERM *cast;

				cast = erl_element(2, fmsg);
				handle_gen_cast(w->fd, cast);
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

	LIST_INSERT_HEAD(&controllers, cnt, controllers);
}

static void usage(void)
{
        printf("TPLINO CAPWAP Data Path Deamon, Version: .....\n\n"
               "Usage: capwap-dp [OPTION...]\n\n"
               "Options:\n\n"
               "  -h                                this help\n"
//               "  --dist=IP                         bind Erlang cluster protocol to interface\n"
               "  --sname=NAME                      Erlang node short name\n"
	       "  -p, --port=PORT                   bind CAPWAP to PORT (default 5247)\n"
//               "  -i, --bind=BIND                   bind CAPWAP to IP\n"
	       "  -n, --netns=NAMESPACE             open CAPWAP socket in namespace\n"
               "  -f, --forward-netns=NAMESPACE     create TAP interface in namespace\n"
               "\n");

        exit(EXIT_SUCCESS);
}

int capwap_port = 5247;
const char *capwap_ns = NULL;
const char *fwd_ns = NULL;

static const char *sname = "capwap-dp";

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
	struct ev_loop *loop = EV_DEFAULT;
	int on = 1;

        int c;
	socklen_t slen;
	int control_fd;
	ev_io control_ev;

        /* unlimited size for cores */
        setrlimit(RLIMIT_CORE, &rlim);

        while (1) {
                int option_index = 0;
                static struct option long_options[] = {
                        {"sname",         1, 0, 1024},
                        {"forward-netns", 1, 0, 'f'},
                        {"netns",         1, 0, 'n'},
                        {"port",          1, 0, 'p'},
                        {0, 0, 0, 0}
                };

                c = getopt_long(argc, argv, "hi:f:n:",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'h':
                        usage();
                        break;

		case 1024:
			sname = strdup(optarg);
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

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	init_netns();
	erl_init(NULL, 0);

	if ((control_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0)
		exit(EXIT_FAILURE);

	setsockopt(control_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (bind(control_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("error bind: %m\n");
		exit(EXIT_FAILURE);
	}

	slen = sizeof(addr);
	if (getsockname(control_fd, (struct sockaddr *)&addr, &slen) < 0) {
		printf("error getsockname: %m\n");
		exit(EXIT_FAILURE);
	}

	if (ei_connect_init(&ec, sname, "cookie", 0) < 0) {
		fprintf(stderr,"ERROR when initializing: %d",erl_errno);
		exit(EXIT_FAILURE);
	}

	if (ei_publish(&ec, ntohs(addr.sin_port)) < 0) {
		fprintf(stderr,"unable to register with EPMD: %d", erl_errno);
		exit(EXIT_FAILURE);
	}

	listen(control_fd, 5);

	ev_io_init(&control_ev, control_cb, control_fd, EV_READ);
	ev_io_start(loop, &control_ev);

	start_worker(8);

	printf("starting loop\n");
	ev_run(loop, 0);

        return 0;
}
