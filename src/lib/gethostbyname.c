/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org> 2008-2011 -
 * Robert Hogan <robert@roberthogan.net> 2013 - David Goulet
 * <dgoulet@ev0ke.net>
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
#include <stdlib.h>

#include <common/log.h>

#include "torsocks.h"

struct hostent tsocks_he;
char *tsocks_he_addr_list[2];
char tsocks_he_addr[INET_ADDRSTRLEN];
char tsocks_he_name[255];

/* gethostbyname(3) */
TSOCKS_LIBC_DECL(gethostbyname, LIBC_GETHOSTBYNAME_RET_TYPE,
		LIBC_GETHOSTBYNAME_SIG)

/* gethostbyname_r(3) */
TSOCKS_LIBC_DECL(gethostbyname_r, LIBC_GETHOSTBYNAME_R_RET_TYPE,
		LIBC_GETHOSTBYNAME_R_SIG)

/* gethostbyname2(3) */
TSOCKS_LIBC_DECL(gethostbyname2, LIBC_GETHOSTBYNAME2_RET_TYPE,
		LIBC_GETHOSTBYNAME2_SIG)

/* gethostbyname2_r(3) */
TSOCKS_LIBC_DECL(gethostbyname2_r, LIBC_GETHOSTBYNAME2_R_RET_TYPE,
		LIBC_GETHOSTBYNAME2_R_SIG)

/* gethostbyaddr(3) */
TSOCKS_LIBC_DECL(gethostbyaddr, LIBC_GETHOSTBYADDR_RET_TYPE,
		LIBC_GETHOSTBYADDR_SIG)

/* gethostbyaddr_r(3) */
TSOCKS_LIBC_DECL(gethostbyaddr_r, LIBC_GETHOSTBYADDR_R_RET_TYPE,
		LIBC_GETHOSTBYADDR_R_SIG)

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: This call is OBSOLETE in the glibc.
 */
LIBC_GETHOSTBYNAME_RET_TYPE tsocks_gethostbyname(LIBC_GETHOSTBYNAME_SIG)
{
	int ret;
	uint32_t ip;

	DBG("[gethostbyname] Requesting %s hostname", name);

	if (!name) {
		h_errno = HOST_NOT_FOUND;
		goto error;
	}

	/* Resolve the given hostname through Tor. */
	ret = tsocks_tor_resolve(AF_INET, name, &ip);
	if (ret < 0) {
		goto error;
	}

	/* Reset static host entry of tsocks. */
	memset(&tsocks_he, 0, sizeof(tsocks_he));
	memset(tsocks_he_addr_list, 0, sizeof(tsocks_he_addr_list));
	memset(tsocks_he_addr, 0, sizeof(tsocks_he_addr));

	/* Copy resolved network byte order IP address. */
	memcpy(tsocks_he_addr, &ip, sizeof(tsocks_he_addr));

	tsocks_he_addr_list[0] = tsocks_he_addr;
	tsocks_he_addr_list[1] = NULL;

	tsocks_he.h_name = (char *) name;
	tsocks_he.h_aliases = NULL;
	tsocks_he.h_length = sizeof(in_addr_t);
	tsocks_he.h_addrtype = AF_INET;
	tsocks_he.h_addr_list = tsocks_he_addr_list;

	DBG("[gethostbyname] Hostname %s resolved to %u.%u.%u.%u", name,
			ip & 0XFF, (ip >> 8) & 0XFF, (ip >> 16) & 0XFF, (ip >> 24) & 0xFF);

	errno = 0;
	return &tsocks_he;

error:
	return NULL;
}

/*
 * Libc hijacked symbol gethostbyname(3).
 */
LIBC_GETHOSTBYNAME_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyname(LIBC_GETHOSTBYNAME_ARGS);
}

/*
 * Torsocks call for gethostbyname2(3).
 *
 * This call, like gethostbyname(), returns pointer to static data thus is
 * absolutely not reentrant.
 */
LIBC_GETHOSTBYNAME2_RET_TYPE tsocks_gethostbyname2(LIBC_GETHOSTBYNAME2_SIG)
{
	/*
	 * For now, there is no way of resolving a domain name to IPv6 through Tor
	 * so only accept INET request thus using the original gethostbyname().
	 */
	if (af != AF_INET) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	return tsocks_gethostbyname(name);
}

/*
 * Libc hijacked symbol gethostbyname2(3).
 */
LIBC_GETHOSTBYNAME2_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyname2(LIBC_GETHOSTBYNAME2_ARGS);
}

/*
 * Torsocks call for gethostbyaddr(3).
 *
 * NOTE: This call is OBSOLETE in the glibc. Also, this call returns a pointer
 * to a static pointer.
 */
LIBC_GETHOSTBYADDR_RET_TYPE tsocks_gethostbyaddr(LIBC_GETHOSTBYADDR_SIG)
{
	int ret;
	char *hostname;

	/*
	 * Tor does not allow to resolve to an IPv6 pointer so only accept inet
	 * return address.
	 */
	if (!addr || type != AF_INET) {
		h_errno = HOST_NOT_FOUND;
		goto error;
	}

	DBG("[gethostbyaddr] Requesting address %s of len %d and type %d",
			inet_ntoa(*((struct in_addr *) addr)), len, type);

	/* Reset static host entry of tsocks. */
	memset(&tsocks_he, 0, sizeof(tsocks_he));
	memset(tsocks_he_addr_list, 0, sizeof(tsocks_he_addr_list));
	memset(tsocks_he_name, 0, sizeof(tsocks_he_name));

	ret = tsocks_tor_resolve_ptr(addr, &hostname, type);
	if (ret < 0) {
		const char *ret_str;

		ret_str = inet_ntop(type, addr, tsocks_he_name,
				sizeof(tsocks_he_name));
		if (!ret_str) {
			h_errno = HOST_NOT_FOUND;
			goto error;
		}
	} else {
		memcpy(tsocks_he_name, hostname, sizeof(tsocks_he_name));
		free(hostname);
		tsocks_he_addr_list[0] = (char *) addr;
	}

	tsocks_he.h_name = tsocks_he_name;
	tsocks_he.h_aliases = NULL;
	tsocks_he.h_length = strlen(tsocks_he_name);
	tsocks_he.h_addrtype = type;
	tsocks_he.h_addr_list = tsocks_he_addr_list;

	errno = 0;
	return &tsocks_he;

error:
	return NULL;
}

/*
 * Libc hijacked symbol gethostbyaddr(3).
 */
LIBC_GETHOSTBYADDR_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyaddr(LIBC_GETHOSTBYADDR_ARGS);
}

/*
 * Torsocks call for gethostbyaddr_r(3).
 *
 * NOTE: GNU extension. Reentrant version.
 */
LIBC_GETHOSTBYADDR_R_RET_TYPE tsocks_gethostbyaddr_r(LIBC_GETHOSTBYADDR_R_SIG)
{
	int ret;
	struct hostent *he = NULL;

	struct data {
		char *hostname;
		char *addr_list[2];
		char padding[];
	} *data;

	if (buflen < sizeof(struct data)) {
		ret = ERANGE;
		goto error;
	}
	data = (struct data *) buf;
	memset(data, 0, sizeof(*data));

	/*
	 * Tor does not allow to resolve to an IPv6 pointer so only accept inet
	 * return address.
	 */
	if (!addr || type != AF_INET) {
		ret = HOST_NOT_FOUND;
		if (h_errnop) {
			*h_errnop = HOST_NOT_FOUND;
		}
		goto error;
	}

	DBG("[gethostbyaddr_r] Requesting address %s of len %d and type %d",
			inet_ntoa(*((struct in_addr *) addr)), len, type);

	/* This call allocates hostname. On error, it's untouched. */
	ret = tsocks_tor_resolve_ptr(addr, &data->hostname, type);
	if (ret < 0) {
		const char *ret_str;

		ret_str = inet_ntop(type, addr, buf, buflen);
		if (!ret_str) {
			ret = HOST_NOT_FOUND;
			if (errno == ENOSPC) {
				ret = ERANGE;
			}
			if (h_errnop) {
				*h_errnop = HOST_NOT_FOUND;
			}
			goto error;
		}
	}

	/* Ease our life a bit. */
	he = hret;

	if (!he) {
		ret = NO_RECOVERY;
		if (h_errnop) {
			*h_errnop = NO_RECOVERY;
		}
		goto error;
	}

	if (data->hostname) {
		he->h_name = data->hostname;
	} else {
		ret = NO_RECOVERY;
		if (h_errnop) {
			*h_errnop = NO_RECOVERY;
		}
		goto error;
	}

	he->h_aliases = NULL;
	he->h_length = strlen(he->h_name);
	/* Assign the address list within the data of the given buffer. */
	data->addr_list[0] = (char *) addr;
	data->addr_list[1] = NULL;
	he->h_addr_list = data->addr_list;

	if (result) {
		*result = he;
	}

	/* Everything went good. */
	ret = 0;

error:
	return ret;
}

/*
 * Libc hijacked symbol gethostbyaddr_r(3).
 */
LIBC_GETHOSTBYADDR_R_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyaddr_r(LIBC_GETHOSTBYADDR_R_ARGS);
}

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: GNU extension. Reentrant version.
 */
LIBC_GETHOSTBYNAME_R_RET_TYPE tsocks_gethostbyname_r(LIBC_GETHOSTBYNAME_R_SIG)
{
	int ret;
	/* This call is always using AF_INET. */
	uint32_t ip;
	const char *ret_str;
	struct hostent *he = NULL;

	struct data {
		char addr[INET_ADDRSTRLEN];
		char *addr_list[2];
		char padding[];
	} *data;

	DBG("[gethostbyname_r] Requesting %s hostname", name);

	if (!name) {
		*h_errnop = HOST_NOT_FOUND;
		ret = -1;
		goto error;
	}

	if (buflen < sizeof(*data)) {
		ret = ERANGE;
		goto error;
	}

	/* Resolve the given hostname through Tor. */
	ret = tsocks_tor_resolve(AF_INET, name, &ip);
	if (ret < 0) {
		goto error;
	}

	data = (struct data *) buf;
	memset(data, 0, sizeof(*data));
	/* Ease our life a bit. */
	he = hret;

	ret_str = inet_ntop(AF_INET, &ip, data->addr, sizeof(data->addr));
	if (!ret_str) {
		PERROR("inet_ntop");
		*h_errnop = NO_ADDRESS;
		goto error;
	}

	memcpy(data->addr, &ip, sizeof(ip));
	data->addr_list[0] = data->addr;
	data->addr_list[1] = NULL;
	he->h_addr_list = data->addr_list;

	he->h_name = (char *) name;
	he->h_aliases = NULL;
	he->h_length = sizeof(in_addr_t);
	he->h_addrtype = AF_INET;

	DBG("[gethostbyname_r] Hostname %s resolved to %u.%u.%u.%u", name,
			ip & 0XFF, (ip >> 8) & 0XFF, (ip >> 16) & 0XFF, (ip >> 24) & 0xFF);

error:
	return ret;
}

/*
 * Libc hijacked symbol gethostbyname_r(3).
 */
LIBC_GETHOSTBYNAME_R_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyname_r(LIBC_GETHOSTBYNAME_R_ARGS);
}

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: GNU extension. Reentrant version.
 */
LIBC_GETHOSTBYNAME2_R_RET_TYPE tsocks_gethostbyname2_r(LIBC_GETHOSTBYNAME2_R_SIG)
{
	DBG("[gethostbyname2_r] Requesting %s hostname", name);

	/*
	 * For now, there is no way of resolving a domain name to IPv6 through Tor
	 * so only accept INET request thus using the original gethostbyname().
	 */
	if (af != AF_INET) {
		*h_errnop = HOST_NOT_FOUND;
		return -1;
	}

	return tsocks_gethostbyname_r(name, hret, buf, buflen, result,
			h_errnop);
}

/*
 * Libc hijacked symbol gethostbyname2_r(3).
 */
LIBC_GETHOSTBYNAME2_R_DECL
{
	tsocks_initialize();
	return tsocks_gethostbyname2_r(LIBC_GETHOSTBYNAME2_R_ARGS);
}
