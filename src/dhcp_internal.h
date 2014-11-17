/*
 *    __                        __      _
 *   / /__________ __   _____  / /___  (_)___  ____ _
 *  / __/ ___/ __ `/ | / / _ \/ / __ \/ / __ \/ __ `/
 * / /_/ /  / /_/ /| |/ /  __/ / /_/ / / / / / /_/ /
 * \__/_/   \__,_/ |___/\___/_/ .___/_/_/ /_/\__, /
 *                           /_/            /____/
 *
 * (c) Travelping GmbH <info@travelping.com>
 *
 */

#ifndef __DHCP_INTERNAL_H
#define __DHCP_INTERNAL_H

#define DHCP_CLIENT_PORT  68
#define DHCP_SERVER_PORT  67

#define BOOTREQUEST              1
#define BOOTREPLY                2

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define DHCP_COOKIE              0x63538263
#else
#define DHCP_COOKIE              0x63825363
#endif

#define BOOTP                    0
#define DHCPDISCOVER             1
#define DHCPOFFER                2
#define DHCPREQUEST              3
#define DHCPDECLINE              4
#define DHCPACK                  5
#define DHCPNAK                  6
#define DHCPRELEASE              7
#define DHCPINFORM               8

#define DHCP_CHADDR_LEN   16
#define DHCP_SNAME_LEN    64
#define DHCP_FILE_LEN    128

#define DHCP_MAX_REPLY_LEN   1500

struct dhcp_packet {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;

	uint32_t xid;

	uint16_t secs;
	uint16_t flags;

	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;

	uint8_t chaddr[DHCP_CHADDR_LEN];
	uint8_t sname[DHCP_SNAME_LEN];
	uint8_t file[DHCP_FILE_LEN];

	uint8_t options[];
} __attribute__ ((packed));

struct dhcp_opt {
	uint8_t op;
	uint8_t len;

	uint8_t data[];
} __attribute__ ((packed));

/* RFC 1533 options */

#define OPT_PAD                 0
#define OPT_END               255

#define OPT_SUBNET_MASK         1
#define OPT_TIME_OFFSET         2
#define OPT_ROUTER              3
#define OPT_TIME_SERVER         4
#define OPT_NAME_SERVER         5
#define OPT_DNSSERVER           6
#define OPT_LOG_SERVER          7
#define OPT_COOKIE_SERVER       8
#define OPT_LPR_SERVER          9
#define OPT_IMPRESS_SERVER     10
#define OPT_RLP_SERVER         11
#define OPT_HOSTNAME           12
#define OPT_BOOT_FILE_SIZE     13
#define OPT_MERIT_DUMP_FILE    14
#define OPT_DOMAINNAME         15
#define OPT_BROADCAST          28
#define OPT_VENDOR_SPECIFIC    43
#define OPT_REQUESTED_IP       50
#define OPT_LEASE_TIME         51
#define OPT_OVERLOAD           52
#define OPT_MESSAGE_TYPE       53
#define OPT_SERVER_IDENTIFIER  54
#define OPT_REQUESTED_OPTS     55
#define OPT_MESSAGE            56
#define OPT_MAXMESSAGE         57
#define OPT_T1                 58
#define OPT_T2                 59
#define OPT_VENDOR_ID          60
#define OPT_CLIENT_ID          61
#define OPT_SNAME              66
#define OPT_FILENAME           67
#define OPT_USER_CLASS         77
#define OPT_CLIENT_FQDN        81
#define OPT_AGENT_ID           82
#define OPT_AUTO_CONFIGURE    116
#define OPT_SUBNET_SELECT     118

#define AGENT_OPT_CIRCUIT_ID            1
#define AGENT_OPT_REMOTE_ID             2
#define AGENT_OPT_LINK_SELECTION        5
#define AGENT_OPT_SUBSCRIBER_ID         6
#define AGENT_OPT_RADIUS_ATTRS          7
#define AGENT_OPT_AUTHENTICATION        8
#define AGENT_OPT_VENDOR                9
#define AGENT_OPT_RELAY_FLAGS          10
#define AGENT_OPT_SERVER_ID_OVERRIDE   11

#endif
