/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org> 
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
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

#include <arpa/inet.h>
#include <assert.h>

#include <common/log.h>

#include "torsocks.h"

/* getaddrinfo(3) */
TSOCKS_LIBC_DECL(getaddrinfo, LIBC_GETADDRINFO_RET_TYPE,
		LIBC_GETADDRINFO_SIG)

/*
 * Torsocks call for getaddrinfo(3).
 */
LIBC_GETADDRINFO_RET_TYPE tsocks_getaddrinfo(LIBC_GETADDRINFO_SIG)
{
	int ret, af;
	struct in_addr addr4;
	struct in6_addr addr6;
	void *addr;
	char *ip_str, ipv4[INET_ADDRSTRLEN], ipv6[INET6_ADDRSTRLEN];
	socklen_t ip_str_size;
	const char *tmp_node;

	DBG("[getaddrinfo] Requesting %s hostname", node);

	if (!node) {
		/*
		 * As stated in the man page, if node is NULL, the libc call will
		 * return a valid socket address but NO external DNS resolution is
		 * possible since there is no host name to resolve.
		 */
		tmp_node = node;
		goto libc_call;
	}

	/*
	 * Quoting the getaddrinfo(3) man page:
	 *
	 * All  the  other  fields  in  the  structure pointed to by hints must
	 * contain either 0 or a NULL pointer, as appropriate.  Specifying  hints
	 * as  NULL  is equivalent  to  setting  ai_socktype  and  ai_protocol  to
	 * 0;  ai_family to AF_UNSPEC; and ai_flags to (AI_V4MAPPED |
	 * AI_ADDRCONFIG).
	 *
	 * This means that for sure the ai_family will be treated as AF_UNSPEC.
	 */
	if (!hints) {
		tmp_node = node;
		goto libc_call;
	}

	/* Use right domain for the next step. */
	switch (hints->ai_family) {
	default:
		/* Default value is to use IPv4. */
	case AF_INET:
		addr = &addr4;
		ip_str = ipv4;
		ip_str_size = sizeof(ipv4);
		af = AF_INET;
		break;
	case AF_INET6:
		addr = &addr6;
		ip_str = ipv6;
		ip_str_size = sizeof(ipv6);
		af = AF_INET6;
		break;
	}

	ret = inet_pton(af, node, addr);
	if (ret == 0) {
		/* If AI_NUMERICHOST is set, return a error. */
		if (hints->ai_flags & AI_NUMERICHOST) {
			ret = EAI_NONAME;
			goto error;
		}

		/* The node most probably is a DNS name. */
		ret = tsocks_tor_resolve(af, node, addr);
		if (ret < 0) {
			ret = EAI_FAIL;
			goto error;
		}

		(void) inet_ntop(af, addr, ip_str, ip_str_size);
		tmp_node = ip_str;
		DBG("[getaddrinfo] Node %s resolved to %s", node,tmp_node);
	} else {
		tmp_node = node;
		DBG("[getaddrinfo] Node %s will be passed to the libc call", tmp_node);
	}

libc_call:
	ret = tsocks_libc_getaddrinfo(tmp_node, service, hints, res);
	if (ret) {
		goto error;
	}

	return 0;

error:
	return ret;
}

/*
 * Libc hijacked symbol getaddrinfo(3).
 */
LIBC_GETADDRINFO_DECL
{
	if (!tsocks_libc_getaddrinfo) {
		tsocks_initialize();
		tsocks_libc_getaddrinfo = tsocks_find_libc_symbol(
				LIBC_GETADDRINFO_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_getaddrinfo(LIBC_GETADDRINFO_ARGS);
}
