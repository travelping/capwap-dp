/*
 * Copyright (C) 2014-2018, Travelping GmbH <info@travelping.com>
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

#include <sys/uio.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <ev.h>

#include <urcu.h>		    /* RCU flavor */
#include <urcu/ref.h>		/* ref counting */
#include <urcu/rcuhlist.h>  /* RCU hlist */
#include <urcu/rculfhash.h>	/* RCU Lock-free hash table */
#include <urcu/compiler.h>	/* For CAA_ARRAY_SIZE */

#include "log.h"
#include "capwap-dp.h"
#include "ieee8023.h"

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

static int send_icmp_pkt_to_big(struct worker *w, unsigned int mtu,
        const unsigned char *buffer, ssize_t len)
{
	struct ether_header *ether_in = (struct ether_header *)buffer;
	struct ether_header *ether_out;
	struct iovec iov[2];
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
        unsigned int room;
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

int ieee8023_to_sta(struct worker *w, const unsigned char *mac, uint16_t vlan,
			   const unsigned char *buffer, ssize_t len)
{
	struct station *sta;
	struct client *wtp = NULL;

	debug("STA MAC: " PRIsMAC, ARGsMAC(mac));

	rcu_read_lock();

	sta = find_station(mac);

	if (!sta) {
		goto out_unlock;
    }

    if (vlan != VLAN_PASS) {
        if (VLAN_ID(sta->vlan) != VLAN_ID(vlan)) {
            goto out_unlock;
        }
    }

	wtp = rcu_dereference(sta->wtp);
	if (wtp) {
		/* the STA and WTP pointers are under RCU protection, so no-one will free them
		 * as long as we hold the RCU read lock */

		debug("found STA %p, WTP %p", sta, wtp);

		uatomic_inc(&sta->send_pkts);
		uatomic_add(&sta->send_bytes, len);

		/* queue packet to WTP */
		ieee8023_to_wtp(w, wtp, sta->rid, NULL, 0, buffer, len);
	}

out_unlock:
	rcu_read_unlock();
	return 1;
}

int ieee8023_bcast_to_wtps(struct worker *w, uint16_t vlan, const unsigned char *buffer, ssize_t len)
{
	struct cds_lfht_iter iter;      /* For iteration on hash table */
	struct client *wtp;
	struct wlan *wlan;
	struct ieee80211_wbinfo wbinfo[MAX_RADIOS];

	memset(wbinfo, 0, sizeof(wbinfo));

	rcu_read_lock();

	cds_lfht_for_each_entry(ht_clients, &iter, wtp, node) {
		debug("WTP %p, stations: %d", wtp, uatomic_read(&wtp->sta_count));

		if (uatomic_read(&wtp->sta_count) == 0)
			continue;

		cds_hlist_for_each_entry_rcu_2(wlan, &wtp->wlans, wlan_list) {
			if (VLAN_ID(wlan->vlan) != VLAN_ID(vlan))
				continue;

			wbinfo[wlan->rid].wlan_id_bitmap |= htons(1 << (wlan->wlan_id - 1));
		}

		/* queue packet to WTP */
		for (int rid = 1; rid < MAX_RADIOS; rid++) {
			if (wbinfo[rid].wlan_id_bitmap == 0)
				continue;

			wbinfo[rid].length = 4;
			ieee8023_to_wtp(w, wtp, rid, (unsigned char *)&wbinfo[rid],
					sizeof(struct ieee80211_wbinfo), buffer, len);
		}
	}

	rcu_read_unlock();

	return 1;
}

int ieee8023_to_wtp(struct worker *w, struct client *wtp, unsigned int rid,
			   const unsigned char *wbinfo, ssize_t wbinfo_len,
			   const unsigned char *buffer, ssize_t len)
{
	ssize_t r __attribute__((unused));
	struct iovec iov[2];
	struct msghdr mh;
	int piov;

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

	if (wbinfo != NULL && wbinfo_len != 0)
		hlen += (wbinfo_len + 3) / 4;

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
					(rid << CAPWAP_RID_SHIFT) |
					(CAPWAP_802_11_PAYLOAD << CAPWAP_WBID_SHIFT));

	if (wbinfo != NULL && wbinfo_len != 0)
		((uint32_t *)chdr)[0] |= CAPWAP_F_WSI;

	if (is_frag) {
		((uint32_t *)chdr)[0] |= CAPWAP_F_FRAG;
		uatomic_inc(&w->send_fragments);
		uatomic_inc(&wtp->send_fragments);
	}
	((uint32_t *)chdr)[1] = htobe32(frag_id << CAPWAP_FRAG_ID_SHIFT);

	/* The message header contains parameters for sendmsg.    */
	memset(&mh, 0, sizeof(mh));
	mh.msg_name = (caddr_t)&wtp->addr;
	mh.msg_namelen = sizeof(wtp->addr);
	mh.msg_iov = iov;

	iov[0].iov_base = chdr;
	iov[0].iov_len = hlen * 4;

	piov = 1;
	if (wbinfo != NULL && wbinfo_len != 0) {
		/* WSI */
		iov[piov].iov_base = (unsigned char *)wbinfo;
		iov[piov].iov_len = wbinfo_len;
		piov++;
	}

	iov[piov].iov_base = (unsigned char *)buffer;
	iov[piov].iov_len = frag_size;

	mh.msg_iovlen = piov + 1;

	ssize_t offs = 0;

	for (; frag_count > 0; frag_count--) {
		debug("Id: %d, Count: %d", frag_id, frag_count);
		if (caa_unlikely(is_frag)) {
			SET_CAPWAP_HEADER_FIELD(&((uint32_t *)chdr)[1], offs / 8, CAPWAP_FRAG_OFFS_MASK, CAPWAP_FRAG_OFFS_SHIFT);
			if (frag_count == 1) {
				((uint32_t *)chdr)[0] |= CAPWAP_F_LASTFRAG;
				iov[piov].iov_len = len % frag_size;
			}
		}

		/* FIXME: shortcat write, we do want to use NON-BLOCKING send here and
		 *        switch to write_ev should it block....
		 */
		if ((r = sendmsg(w->capwap_fd, &mh, MSG_DONTWAIT)) < 0)
			debug("sendmsg: %m");

		debug("fwd tap sendmsg: %zd", r);

		if (r > 0) {
			uatomic_inc(&w->send_pkts);
			uatomic_inc(&wtp->send_pkts);
			uatomic_add(&w->send_bytes, r);
			uatomic_add(&wtp->send_bytes, r);
		}

		if (caa_unlikely(((uint32_t *)chdr)[0] & CAPWAP_F_WSI)) {
			/* don't send WSI on following fragements */
			piov--;
			mh.msg_iovlen--;

			((uint32_t *)chdr)[0] &= ~CAPWAP_F_WSI;
			iov[piov].iov_base = (unsigned char *)buffer;
			iov[piov].iov_len = frag_size;
		}

		iov[piov].iov_base = (unsigned char *)iov[piov].iov_base + frag_size;
		offs += frag_size;
	}

	return 1;
}

struct ether_header* fill_raw_udp_packet(void *data, uint16_t data_len,
        struct in_addr *saddr, uint8_t *mac_shost,
        struct in_addr *daddr, uint8_t *mac_dhost, uint16_t *send_len)
{
    uint8_t *datagram, *data_buf;
    uint16_t ip_tot_len, tot_len;
    uint32_t udp_csum;

    ip_tot_len = data_len + sizeof(struct iphdr) + sizeof(struct udphdr);
    tot_len = ip_tot_len + sizeof(struct ether_header);
    *send_len = tot_len;

    datagram = (uint8_t *) calloc(1, tot_len);

    struct udp_pheader psh;

    struct ether_header *eh = (struct ether_header *) datagram;

    struct iphdr *iph = (struct iphdr *) (datagram +
            sizeof(struct ether_header));
    struct udphdr *udph = (struct udphdr *) (datagram +
            sizeof(struct ether_header) + sizeof(struct iphdr));

    data_buf = datagram + sizeof(struct ether_header) + sizeof(struct iphdr) +
        sizeof(struct udphdr);
    memcpy(data_buf, data, data_len);

    // Ethernet frame
    eh->ether_type = htons(ETH_P_IP);
    memcpy(eh->ether_shost, mac_shost, 6);
    memcpy(eh->ether_dhost, mac_dhost, 6);

    // IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(ip_tot_len);
    iph->id = htons(0);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    // Source ip
    iph->saddr = saddr->s_addr;
    // Dest ip
    iph->daddr = daddr->s_addr;

    // Ip checksum
    iph->check = cksum((uint8_t *)iph, sizeof(struct iphdr));

    //UDP header
    udph->source = htons(67);
    udph->dest = htons(68);
    udph->len = htons(sizeof(struct udphdr) + data_len);

    //Now the UDP checksum using the pseudo header
    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = htons(sizeof(struct udphdr) + data_len);

    // Udp checksum
    udp_csum = cksum_part((uint8_t*)&psh, sizeof(struct udp_pheader), 0);
    udp_csum = cksum_part((uint8_t*)udph, sizeof(struct udphdr), udp_csum);
    udp_csum = cksum_part((uint8_t*)data, data_len, udp_csum);
    udph->check = cksum_finish(udp_csum);

    return eh;
}

