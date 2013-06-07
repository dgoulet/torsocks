/*
 * Structure used by torsocks to form SOCKS requests.
 *
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef TORSOCKS_SOCKS_H
#define TORSOCKS_SOCKS_H

#include <stdint.h>

#include "connection.h"

/* For SOCKS version 5. */
#define SOCKS5_VERSION			0x05

/*
 * As stated in the SOCKS extension of Tor, for v5 the "NO AUTHENTICATION
 * METHOD" [00] is supported and should be used.
 */
#define SOCKS5_NO_AUTH_METHOD	0x00

/* Request to connect. */
#define SOCKS5_CMD_CONNECT		0x01

/* Address type. */
#define SOCKS5_ATYP_IPV4		0x01
#define SOCKS5_ATYP_DOMAIN		0x03
#define SOCKS5_ATYP_IPV6		0x04

/* Replies code. */
#define SOCKS5_REPLY_SUCCESS	0x00
#define SOCKS5_REPLY_FAIL		0x01
#define SOCKS5_REPLY_DENY_RULE	0x02
#define SOCKS5_REPLY_NO_NET		0x03
#define SOCKS5_REPLY_NO_HOST	0x04
#define SOCKS5_REPLY_REFUSED	0x05
#define SOCKS5_REPLY_TTL_EXP	0x06
#define SOCKS5_REPLY_CMD_NOTSUP	0x07
#define SOCKS5_REPLY_ADR_NOTSUP	0x08

/* Request data structure for the method. */
struct socks5_method_req {
	uint8_t ver;
	uint8_t nmethods;
};

/* Reply data structure for the method. */
struct socks5_method_res {
	uint8_t ver;
	uint8_t method;
};

/* First part of a request. */
struct socks5_request {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
};

/* IPv4 destination addr for a request. */
struct socks5_request_ipv4 {
	uint8_t len;
	uint8_t addr[4];
	uint16_t port;
};

/* IPv6 destination addr for a request. */
struct socks5_request_ipv6 {
	uint8_t len;
	uint8_t addr[16];
	uint16_t port;
};

/* Domain name for a request. */
struct socks5_request_domain {
	uint8_t len;
	/* Maximum size of len above. No NULL byte is needed. */
	char name[UINT8_MAX];
	uint16_t port;
};

/* Non variable part of a reply. */
struct socks5_reply {
	uint8_t ver;
	uint8_t rep;
	uint8_t rsv;
	uint8_t atyp;
};

#endif /* TORSOCKS_SOCKS_H */
