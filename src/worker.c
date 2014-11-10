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
#include <pthread.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>
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

#include "capwap-dp.h"
#include "netns.h"

struct worker *workers;

struct cds_lfht *ht_stations;	/* Hash table */
struct cds_lfht *ht_clients;	/* Hash table */

static int capwap_ns_fd = 0;
static int fwd_ns_fd = 0;

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
	struct station *sta = caa_container_of(head, struct station, rcu_head);
	free(sta);
}

static void ref_free_station(struct urcu_ref *ref)
{
	struct station *sta = caa_container_of(ref, struct station, ref);
	call_rcu(&sta->rcu_head, rcu_free_station);
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

	cds_hlist_add_head_rcu(&sta->wtp_list, &wtp->stations);
	sta->wtp = wtp;
}

void detach_station_from_wtp(struct station *sta)
{
	if (!sta || !sta->wtp)
		return;

	cds_hlist_del_rcu(&sta->wtp_list);
	sta->wtp = NULL;

	refcount_put_station(sta);
	refcount_put_client(sta->wtp);
}

static void hexdump(FILE *stream, const unsigned char *buf, ssize_t len)
{
	ssize_t i;

	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			if (i != 0)
				fprintf(stream, "\n");
			fprintf(stream, "0x%08zx:  ", i);
		}
		fprintf(stream, "%02x ", buf[i]);
	}
	fprintf(stream, "\n");
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

struct station *find_station(uint8_t *ether)
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

struct client *find_wtp(struct sockaddr *addr)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;
	unsigned long hash;

	hash = hash_sockaddr(addr);

	cds_lfht_lookup(ht_clients, hash, match_sockaddr, addr, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (ht_node)
		return caa_container_of(ht_node, struct client, node);

	return NULL;
}

static void stop_cb(EV_P_ ev_async *ev, int revents)
{
	struct worker *w = ev_userdata(EV_A);

	ev_io_stop(EV_A_ &w->capwap_ev);
	ev_async_stop(EV_A_ ev);

	close(w->capwap_ev.fd);

	ev_break(EV_A_ EVBREAK_ALL);
}

unsigned long hash_sockaddr(struct sockaddr *addr)
{
	switch (addr->sa_family) {
	case AF_INET:
		return jhash(&((struct sockaddr_in *)addr)->sin_addr, sizeof(struct in_addr), ((struct sockaddr_in *)addr)->sin_port);


	case AF_INET6:
		return jhash(&((struct sockaddr_in6 *)addr)->sin6_addr, sizeof(struct in6_addr), ((struct sockaddr_in6 *)addr)->sin6_port);
	}

	return jhash(addr, sizeof(addr), 0);
}

static void forward_capwap(struct worker *w, struct sockaddr *addr, struct ether_header *ether, unsigned char *data, unsigned int len)
{
	struct station *sta;
	struct iovec iov[2];
	int r;

	rcu_read_lock();

	fprintf(stderr, "%lx: fwd CW ether: %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid,
		ether->ether_shost[0], ether->ether_shost[1], ether->ether_shost[2],
		ether->ether_shost[3], ether->ether_shost[4], ether->ether_shost[5]);

	if ((sta = find_station(ether->ether_shost)) != NULL) {
		/* queue packet to TAP */

		fprintf(stderr, "%lx: found STA %p, WTP %p\n", w->tid, sta, sta->wtp);
	}

	/* FIXME: shortcat write */
	iov[0].iov_base = ether;
	iov[0].iov_len = ETH_ALEN * 2;
	iov[1].iov_base = data;
	iov[1].iov_len = len;

	r = writev(w->tap_fd, iov, 2);
	fprintf(stderr, "%lx: fwd CW writev: %d\n", w->tid, r);

	rcu_read_unlock();
}

static void capwap_recv(struct worker *w, struct msghdr *msg, unsigned char *buffer, unsigned int len)
{
	char ipaddr[INET6_ADDRSTRLEN];
	struct sockaddr *addr = (struct sockaddr *)msg->msg_name;

	unsigned int hlen;
	unsigned int wbid;
	unsigned char *data;
	unsigned int datalen;

	inet_ntop(addr->sa_family, SIN_ADDR_PTR(addr), ipaddr, sizeof(ipaddr));
	fprintf(stderr, "%lx(%u): read %d bytes from %s:%d\n",
		w->tid, w->id, len, ipaddr, ntohs(SIN_PORT(addr)));
	hexdump(stderr, buffer, len);

	if (len < CAPWAP_HEADER_LEN)
		return;

	hlen = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_HLEN_MASK, CAPWAP_HLEN_SHIFT);
	if (len < hlen)
		return;

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_K, 0))
		/* FIXME: Keep-Alive */
		return;

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_FRAG, 0))
		/* FIXME: no fragmentation support (yet) */
		return;

	data = buffer + hlen;
	datalen = len - hlen;

	if (GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_F_TYPE, 0))
		wbid = GET_CAPWAP_HEADER_FIELD(buffer, CAPWAP_WBID_MASK, CAPWAP_WBID_SHIFT);
	else
		wbid = CAPWAP_802_3_PAYLOAD;

	switch (wbid) {
	case CAPWAP_802_3_PAYLOAD:
		forward_capwap(w, addr, (struct ether_header *)data, data + ETH_ALEN * 2, datalen - ETH_ALEN * 2);
		break;

	case CAPWAP_802_11_PAYLOAD: {
		struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)data;
		struct ether_header *ether;
		uint16_t fc = le_to_host16(hdr->frame_control);

		fprintf(stderr, "FrameType: %04x", fc);

		if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT) {
			/* push mgmt to controller */
			fprintf(stderr, "management frame\n");
			return;
		}
		else if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_DATA &&
			 (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)) == WLAN_FC_FROMDS) {
			fprintf(stderr, "%lx: addr1: %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid,
				hdr->addr1[0], hdr->addr1[1], hdr->addr1[2],
				hdr->addr1[3], hdr->addr1[4], hdr->addr1[5]);
			fprintf(stderr, "%lx: addr2: %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid,
				hdr->addr2[0], hdr->addr2[1], hdr->addr2[2],
				hdr->addr2[3], hdr->addr2[4], hdr->addr2[5]);
			fprintf(stderr, "%lx: addr3: %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid,
				hdr->addr3[0], hdr->addr3[1], hdr->addr3[2],
				hdr->addr3[3], hdr->addr3[4], hdr->addr3[5]);

			ether = (struct ether_header *)&hdr->addr1;
			memcpy(&ether->ether_shost, &hdr->addr3, ETH_ALEN);

			forward_capwap(w, addr, ether, data + sizeof(struct ieee80211_hdr), datalen - sizeof(struct ieee80211_hdr));
		} else {
			/* wrong direction / unknown / unhandled WLAN frame - ignore */
			fprintf(stderr, "ignoring: type %d, To/From %d\n", WLAN_FC_GET_TYPE(fc), (fc & (WLAN_FC_TODS | WLAN_FC_FROMDS)));
			return;
		}
		break;
	}

	default:
		return;
	}
}

#if 0
	struct client *clnt;

	struct cds_lfht_iter iter;
	struct cds_lfht_node *ht_node;
	unsigned long hash;

	hash = hash_sockaddr(addr);

	rcu_read_lock();

	cds_lfht_lookup(ht_clients, hash, match_sockaddr, addr, &iter);
	ht_node = cds_lfht_iter_get_node(&iter);
	if (!ht_node) {
		clnt = calloc(1, sizeof(struct client));

		urcu_ref_init(&clnt->ref);
		cds_lfht_node_init(&clnt->node);
		CDS_INIT_HLIST_HEAD(&clnt->stations);
		memcpy(&clnt->addr, addr, sizeof(clnt->addr));

		cds_lfht_add(ht_clients, hash, &clnt->node);
	} else
		clnt = caa_container_of(ht_node, struct client, node);

	rcu_read_unlock();

	/* do whatever we want */
	fprintf(stderr, "Clnt: %p, new: %d\n", clnt, !ht_node);

	if (!ht_node) {
		/* send new data channel notify to controller */
	}

	/* check if have the client MAC+IP or only MAC */

	/* decapsulate and forward data */
#endif
static void capwap_read_error_q(struct worker *w, int fd)
{
	ssize_t r;
	char buffer[2048];
	struct iovec iov;                       /* Data array */
	struct msghdr msg;                      /* Message header */
	struct cmsghdr *cmsg;                   /* Control related data */
	struct sock_extended_err *sock_err;     /* Struct describing the error */
	struct icmphdr icmph;                   /* ICMP header */
	struct sockaddr_in remote;              /* Our socket */

	for (;;) {
		iov.iov_base = &icmph;
		iov.iov_len = sizeof(icmph);
		msg.msg_name = (void*)&remote;
		msg.msg_namelen = sizeof(remote);
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_flags = 0;
		msg.msg_control = buffer;
		msg.msg_controllen = sizeof(buffer);

		/* Receiving errors flog is set */
		if ((r = recvmsg(fd, &msg, MSG_ERRQUEUE)) < 0)
			break;

		/* Control messages are always accessed via some macros
		 * http://www.kernel.org/doc/man-pages/online/pages/man3/cmsg.3.html
		 */
		for (cmsg = CMSG_FIRSTHDR(&msg);cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))  {
			/* Ip level */
			if (cmsg->cmsg_level == SOL_IP &&
			    cmsg->cmsg_type == IP_RECVERR) {
				fprintf(stderr, "We got IP_RECVERR message\n");
				sock_err = (struct sock_extended_err*)CMSG_DATA(cmsg);
				if (sock_err && sock_err->ee_origin == SO_EE_ORIGIN_ICMP) {
					/* Handle ICMP errors types */
					switch (sock_err->ee_type) {
					case ICMP_NET_UNREACH:
						/* Handle this error */
						fprintf(stderr, "Network Unreachable Error\n");
						break;

					case ICMP_HOST_UNREACH:
						/* Handle this error */
						fprintf(stderr, "Host Unreachable Error\n");
						break;

					case ICMP_PORT_UNREACH:
						/* Handle this error */
						fprintf(stderr, "Port Unreachable Error\n");
						break;

					default:
						/* Handle all other cases. Find more errors :
						 * http://lxr.linux.no/linux+v3.5/include/linux/icmp.h#L39
						 */
						fprintf(stderr, "got Error %d\n", sock_err->ee_type);
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
	struct sockaddr addrs[VLEN];
	struct iovec iovecs[VLEN];
	unsigned char bufs[VLEN][BUFSIZE];

	struct worker *w = ev_userdata (EV_A);

	fprintf(stderr, "%lx: read (%x) from %d\n", w->tid, revents, ev->fd);

	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < VLEN; i++) {
		msgs[i].msg_hdr.msg_name    = &addrs[i];
		msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr);
		iovecs[i].iov_base          = bufs[i];
		iovecs[i].iov_len           = BUFSIZE;
		msgs[i].msg_hdr.msg_iov     = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen  = 1;
	}

	r = recvmmsg(ev->fd, msgs, VLEN, MSG_DONTWAIT, NULL);
	if (r < 0) {
		if (errno == EAGAIN) {
			/* can read, but got no data, must be something in the error queue */
			capwap_read_error_q(w, ev->fd);
			return;
		}
		perror("read");
		return;
	}

	fprintf(stderr, "%lx(%u): %zd CAPWAP messages received\n", w->tid, w->id, r);
	for (i = 0; i < r; i++) {
		fprintf(stderr, "flags: %d\n", msgs[i].msg_hdr.msg_flags);
		capwap_recv(w, &msgs[i].msg_hdr, bufs[i], msgs[i].msg_len);
	}

#undef VLEN
#undef BUFSIZE
}

static void tap_multicast(struct worker *w, unsigned char *buffer, ssize_t len)
{
//	struct ether_header *ether = (struct ether_header *)buffer;
/*
	fprintf(stderr, "%lx: dst mcast ether: %d, %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid, ether->ether_dhost[0] & 0x01,
		ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
		ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
	fprintf(stderr, "%lx: ether mcast type: %04x\n", w->tid, ntohs(ether->ether_type));
*/
}

static void tap_unicast(struct worker *w, unsigned char *buffer, ssize_t len)
{
	ssize_t r;
	struct station *sta;
	struct iovec iov[2];
	struct msghdr mh;
	struct ether_header *ether = (struct ether_header *)buffer;

	fprintf(stderr, "%lx: dst unicast ether: %d, %02x:%02x:%02x:%02x:%02x:%02x\n", w->tid, ether->ether_dhost[0] & 0x01,
		ether->ether_dhost[0], ether->ether_dhost[1], ether->ether_dhost[2],
		ether->ether_dhost[3], ether->ether_dhost[4], ether->ether_dhost[5]);
	fprintf(stderr, "%lx: ether unicast type: %04x\n", w->tid, ntohs(ether->ether_type));

	rcu_read_lock();

	if ((sta = find_station(ether->ether_dhost)) != NULL) {
		/* queue packet to WTP */

		unsigned char chdr[32];

		memset(chdr, 0, sizeof(chdr));

		/* Version = 0, Type = 0, HLen = 8, RId = 1, no WBID, 802.3 encoding */
		((uint32_t *)chdr)[0] = htobe32((8 << CAPWAP_HLEN_SHIFT) | (1 < CAPWAP_RID_SHIFT));

		/* Frag Id = 0, Frag Offset = 0 */
		/* no RADIO MAC */
		/* no WSI */

		/* FIXME: shortcat write */
		iov[0].iov_base = chdr;
		iov[0].iov_len = 8;
		iov[1].iov_base = buffer;
		iov[1].iov_len = len;

		/* The message header contains parameters for sendmsg.    */
		memset(&mh, 0, sizeof(mh));
		mh.msg_name = (caddr_t)&sta->wtp->addr;
		mh.msg_namelen = sizeof(sta->wtp->addr);
		mh.msg_iov = iov;
		mh.msg_iovlen = 2;

		r = sendmsg(w->capwap_fd, &mh, 0);
		fprintf(stderr, "%lx: fwd tap sendmsg: %zd\n", w->tid, r);


		fprintf(stderr, "%lx: found STA %p, WTP %p\n", w->tid, sta, sta->wtp);
	}

	rcu_read_unlock();
}

static void tap_cb(EV_P_ ev_io *ev, int revents)
{
	ssize_t r;
	unsigned char buffer[2048];
	int cnt = 10;
	struct worker *w = ev_userdata (EV_A);

	fprintf(stderr, "%lx: read from %d\n", w->tid, ev->fd);

	while (cnt > 0 && (r = read(ev->fd, buffer, sizeof(buffer))) > 0) {
		struct ether_header *ether = (struct ether_header *)&buffer;

		fprintf(stderr, "%lx: read %zd bytes\n", w->tid, r);
//		hexdump(stderr, buffer, r);

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

int tap_alloc(char *dev)
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

	fprintf(stderr, "allocated TAP device %s\n", dev);
	return fd;
}

void set_if_addr(const char *dev)
{
	int r;
	char cmd[MAXPATHLEN];

	if (fwd_ns)
		snprintf(cmd, sizeof(cmd), "ip netns exec %s /sbin/ifconfig %s 192.168.240.0 netmask 255.255.255.0 up", fwd_ns, dev);
	else
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s 192.168.240.0 netmask 255.255.255.0 up", dev);

	fprintf(stderr, "cmd: '%s'\n", cmd);
	if ((r = system(cmd)) < 0)
		fprintf(stderr, "failed with : '%m'\n");
}

static void *worker_thread(void *arg)
{
	int on = 1;
        struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(capwap_port),
		.sin_addr.s_addr = htonl(INADDR_ANY)
	};
	struct worker *w = (struct worker *)arg;

	/*
	 * Each thread need using RCU read-side need to be explicitly
	 * registered.
	 */
	rcu_register_thread();

	if (capwap_ns_fd)
		w->capwap_fd = socket_ns(capwap_ns_fd, AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	else
		w->capwap_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);

	if (w->capwap_fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	setsockopt(w->capwap_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
	setsockopt(w->capwap_fd, SOL_SOCKET, SO_REUSEPORT, (char*)&on, sizeof(on));
	setsockopt(w->capwap_fd, SOL_IP, IP_RECVERR,(char*)&on, sizeof(on));

	if (bind(w->capwap_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
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

	fprintf(stderr, "worker %lx running\n", w->tid);

	ev_lock(w->loop);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, 0);
	ev_run(w->loop, 0);
	ev_unlock(w->loop);

	ev_loop_destroy(w->loop);
	rcu_unregister_thread();

	fprintf(stderr, "worker %lx exited\n", w->tid);

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
		fwd_ns_fd = get_nsfd(capwap_ns);

	for (int i = 0; i < count; i++) {
		workers[i].id = i;
		if ((workers[i].tap_fd = tap_alloc(tap_dev)) < 0)
			return 0;
		pthread_create(&workers[i].tid, NULL, worker_thread, (void *)&workers[i]);
	}

	set_if_addr(tap_dev);

	return 1;
}