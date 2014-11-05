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
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include <ev.h>

#include <urcu.h>		/* RCU flavor */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */
#include "jhash.h"		/* Example hash function */

#include "capwap-dp.h"

struct client {
	struct cds_lfht_node node;

	struct sockaddr addr;
};
struct cds_lfht *ht_clients;	/* Hash table */

#define SOCK_ADDR_CMP(a, b, socktype, field)				\
	memcmp(&(((struct socktype *)(a))->field),			\
	       &(((struct socktype *)(b))->field),			\
	       sizeof(((struct socktype *)(a))->field))

#define SOCK_PORT_CMP(a, b, socktype, field)				\
	(((struct socktype *)(a))->field == ((struct socktype *)(b))->field)

#define SIN_ADDR_PTR(addr) (((addr).sa_family == AF_INET) ? (void *)&(((struct sockaddr_in *)&(addr))->sin_addr) : (void *)&(((struct sockaddr_in6 *)&(addr))->sin6_addr))
#define SIN_PORT(addr) (((addr).sa_family == AF_INET) ? (((struct sockaddr_in *)&(addr))->sin_port) : (((struct sockaddr_in6 *)&(addr))->sin6_port))

static int match(struct cds_lfht_node *ht_node, const void *_key)
{
	struct client *client = caa_container_of(ht_node, struct client, node);
	const struct sockaddr *key = _key;

	if (client->addr.sa_family != key->sa_family)
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

struct ev_data {
	struct ev_loop *loop;
	pthread_mutex_t lock; /* global loop lock */

	ev_io capwap_ev;
	ev_async stop_ev;
	unsigned int id;
	pthread_t tid;
};

static void stop_cb(EV_P_ ev_async *ev, int revents)
{
	struct ev_data *w = ev_userdata(EV_A);

	ev_io_stop(EV_A_ &w->capwap_ev);
	ev_async_stop(EV_A_ ev);

	close(w->capwap_ev.fd);

	ev_break (EV_A_ EVBREAK_ALL);
}

static unsigned long hash_sockaddr(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return jhash(&((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr), ((struct sockaddr_in *)addr)->sin_port);


	case AF_INET6:
		return jhash(&((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr), ((struct sockaddr_in6 *)addr)->sin6_port);
	}

	return jhash(addr, sizeof(addr), 0);
}

static void capwap_cb(EV_P_ ev_io *ev, int revents)
{
	ssize_t r;
	char buffer[2048];
	char ipaddr[INET6_ADDRSTRLEN];
	struct client *clnt;
	struct sockaddr addr;
	int cnt = 10;
	socklen_t addrlen = sizeof(addr);
	struct ev_data *w = ev_userdata (EV_A);

	fprintf(stderr, "%lx: read from %d\n", w->tid, ev->fd);

	/* TODO: the counter is stupid, use recvmmsg instead */
	while (cnt > 0 && (r = recvfrom(ev->fd, buffer, sizeof(buffer), MSG_DONTWAIT, &addr, &addrlen)) > 0) {
		struct cds_lfht_iter iter;
		struct cds_lfht_node *ht_node;
		unsigned long hash;

		hash = hash_sockaddr(&addr);

		inet_ntop(addr.sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
		fprintf(stderr, "%lx(%u): read %zd bytes from %s:%d on %d, hash: %lx\n",
			w->tid, w->id, r, ipaddr, ntohs(SIN_PORT(addr)), ev->fd, hash);

		rcu_read_lock();

		cds_lfht_lookup(ht_clients, hash, match, &addr, &iter);
		ht_node = cds_lfht_iter_get_node(&iter);
		if (!ht_node) {
			clnt = malloc(sizeof(struct client));
			memset(clnt, 0, sizeof(struct client));
			cds_lfht_node_init(&clnt->node);
			memcpy(&clnt->addr, &addr, sizeof(addr));

			cds_lfht_add(ht_clients, hash, &clnt->node);

		} else {
			clnt = caa_container_of(ht_node, struct client, node);
		}

		rcu_read_unlock();

		/* do whatever we want */
		fprintf(stderr, "Clnt: %p, new: %d\n", clnt, !ht_node);

		if (!ht_node) {
			/* send new data channel notify to controller */
		}

		/* check if have the client MAC+IP or only MAC */

		/* decapsulate and forward data */

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
	struct ev_data *w = ev_userdata (EV_A);
	pthread_mutex_lock(&w->lock);
}

static void ev_unlock(EV_P)
{
	struct ev_data *w = ev_userdata(EV_A);
	pthread_mutex_unlock (&w->lock);
}

static void *worker(void *arg)
{
	int on = 1;
        struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(5247),
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};
	struct ev_data w;
	int capwap_fd;

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	if ((capwap_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(capwap_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	setsockopt(capwap_fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));

	if (bind(capwap_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	w.loop = ev_loop_new(EVFLAG_AUTO);
	w.id = (uintptr_t)arg;
	w.tid = pthread_self();

	ev_async_init(&w.stop_ev, stop_cb);
	ev_async_start(w.loop, &w.stop_ev);

	ev_io_init(&w.capwap_ev, capwap_cb, capwap_fd, EV_READ);
	ev_io_start(w.loop, &w.capwap_ev);

	pthread_mutex_init(&w.lock, 0);

	// now associate this with the loop
	ev_set_userdata(w.loop, &w);
	ev_set_loop_release_cb(w.loop, ev_unlock, ev_lock);

	fprintf(stderr, "worker %lx running\n", w.tid);

	ev_lock(w.loop);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	ev_run(w.loop, 0);
	ev_unlock(w.loop);

	ev_loop_destroy(w.loop);
	rcu_unregister_thread();

	fprintf(stderr, "worker %lx exited\n", w.tid);

	return NULL;
}

int start_worker(unsigned int id)
{
	pthread_t thread;

	if (!ht_clients)
		ht_clients = cds_lfht_new(1, 1, 0,
					  CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
					  NULL);

	return pthread_create(&thread, NULL, worker, (void *)(uintptr_t)id);
}
