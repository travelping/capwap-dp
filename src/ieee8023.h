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

#ifndef __IEEE8023_H
#define __IEEE8023_H

#define VLAN_ID(x)  ((x) & 0x0ffff)
#define VLAN_PASS 0xffff

int ieee8023_to_sta(struct worker *w, const unsigned char *mac, uint16_t vlan,
			   const unsigned char *buffer, ssize_t len);

int ieee8023_bcast_to_wtps(struct worker *w, uint16_t vlan, const unsigned char *buffer, ssize_t len);

int ieee8023_to_wtp(struct worker *w, struct client *wtp, unsigned int rid,
			   const unsigned char *wbinfo, ssize_t wbinfo_len,
			   const unsigned char *buffer, ssize_t len);

struct ether_header* fill_raw_udp_packet(void *data, uint16_t data_len,
        uint32_t saddr, uint8_t *mac_shost,
        uint32_t daddr, uint8_t *mac_dhost, uint16_t *send_len);

#endif // __IEEE8023_H
