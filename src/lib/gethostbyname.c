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

/*
 * Free the given hostent structure and all pointers contained inside.
 */
static void free_hostent(struct hostent *he)
{
	if (!he) {
		return;
	}

	if (he->h_name) {
		free(he->h_name);
	}

	if (he->h_aliases) {
		int i = 0;

		while (he->h_aliases[i] != NULL) {
			free(he->h_aliases[i]);
			i++;
		}
	}

	if (he->h_addr_list) {
		int i = 0;

		while (he->h_addr_list[i] != NULL) {
			free(he->h_addr_list[i]);
			i++;
		}
	}

	free(he);
}

/*
 * Allocate a hostent structure with the given type.
 *
 * On error, return NULL.
 */
static struct hostent *alloc_hostent(int af)
{
	void *addr = NULL;
	char **addr_list = NULL, **aliases = NULL;
	struct hostent *he = NULL;
	size_t addrlen;

	if (af != AF_INET && af != AF_INET6) {
		goto error;
	}

	he = zmalloc(sizeof(*he));
	addr_list = zmalloc(sizeof(*addr_list) * 2);
	aliases = zmalloc(sizeof(*aliases));
	if (!he || !addr_list || !aliases) {
		PERROR("zmalloc hostent");
		goto error;
	}

	switch (af) {
	case AF_INET:
		addr = zmalloc(sizeof(struct in_addr));
		addrlen = sizeof(struct in_addr);
		break;
	case AF_INET6:
		addr = zmalloc(sizeof(struct in6_addr));
		addrlen = sizeof(struct in6_addr);
		break;
	default:
		assert(0);
		goto error;
	}
	if (!addr) {
		PERROR("zmalloc addr");
		goto error;
	}

	he->h_name = NULL;
	he->h_addr_list = addr_list;
	he->h_addr_list[0] = addr;
	he->h_addr_list[1] = NULL;
	he->h_aliases = aliases;
	he->h_aliases[0] = NULL;
	he->h_length = addrlen;
	he->h_addrtype = af;

	return he;

error:
	free_hostent(he);
	return NULL;
}

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: This call is OBSOLETE in the glibc.
 */
LIBC_GETHOSTBYNAME_RET_TYPE tsocks_gethostbyname(LIBC_GETHOSTBYNAME_SIG)
{
	int ret;
	uint32_t ip;
	const char *ret_str;

	DBG("[gethostbyname] Requesting %s hostname", __name);

	if (!__name) {
		h_errno = HOST_NOT_FOUND;
		goto error;
	}

	/* Resolve the given hostname through Tor. */
	ret = tsocks_tor_resolve(__name, &ip);
	if (ret < 0) {
		goto error;
	}

	/* Reset static host entry of tsocks. */
	memset(&tsocks_he, 0, sizeof(tsocks_he));
	memset(tsocks_he_addr_list, 0, sizeof(tsocks_he_addr_list));
	memset(tsocks_he_addr, 0, sizeof(tsocks_he_addr));

	ret_str = inet_ntop(AF_INET, &ip, tsocks_he_addr, sizeof(tsocks_he_addr));
	if (!ret_str) {
		PERROR("inet_ntop");
		h_errno = NO_ADDRESS;
		goto error;
	}

	tsocks_he_addr_list[0] = tsocks_he_addr;
	tsocks_he_addr_list[1] = NULL;

	tsocks_he.h_name = (char *) __name;
	tsocks_he.h_aliases = NULL;
	tsocks_he.h_length = sizeof(in_addr_t);
	tsocks_he.h_addrtype = AF_INET;
	tsocks_he.h_addr_list = tsocks_he_addr_list;

	DBG("Hostname %s resolved to %s", __name, tsocks_he_addr);

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
	if (__af != AF_INET) {
		h_errno = HOST_NOT_FOUND;
		return NULL;
	}

	return tsocks_gethostbyname(__name);
}

/*
 * Libc hijacked symbol gethostbyname2(3).
 */
LIBC_GETHOSTBYNAME2_DECL
{
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
	if (!__addr || __type != AF_INET) {
		h_errno = HOST_NOT_FOUND;
		goto error;
	}

	DBG("[gethostbyaddr] Requesting address %s of len %d and type %d",
			inet_ntoa(*((struct in_addr *) __addr)), __len, __type);

	/* Reset static host entry of tsocks. */
	memset(&tsocks_he, 0, sizeof(tsocks_he));
	memset(tsocks_he_addr_list, 0, sizeof(tsocks_he_addr_list));
	memset(tsocks_he_name, 0, sizeof(tsocks_he_name));

	ret = tsocks_tor_resolve_ptr(__addr, &hostname, __type);
	if (ret < 0) {
		const char *ret_str;

		ret_str = inet_ntop(__type, __addr, tsocks_he_name,
				sizeof(tsocks_he_name));
		if (!ret_str) {
			h_errno = HOST_NOT_FOUND;
			goto error;
		}
	} else {
		memcpy(tsocks_he_name, hostname, sizeof(tsocks_he_name));
		free(hostname);
		tsocks_he_addr_list[0] = (char *) __addr;
	}

	tsocks_he.h_name = tsocks_he_name;
	tsocks_he.h_aliases = NULL;
	tsocks_he.h_length = strlen(tsocks_he_name);
	tsocks_he.h_addrtype = __type;
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

	if (__buflen < sizeof(struct data)) {
		ret = ERANGE;
		goto error;
	}
	data = (struct data *) __buf;
	memset(data, 0, sizeof(*data));

	/*
	 * Tor does not allow to resolve to an IPv6 pointer so only accept inet
	 * return address.
	 */
	if (!__addr || __type != AF_INET) {
		ret = HOST_NOT_FOUND;
		if (__h_errnop) {
			*__h_errnop = HOST_NOT_FOUND;
		}
		goto error;
	}

	DBG("[gethostbyaddr_r] Requesting address %s of len %d and type %d",
			inet_ntoa(*((struct in_addr *) __addr)), __len, __type);

	/* This call allocates hostname. On error, it's untouched. */
	ret = tsocks_tor_resolve_ptr(__addr, &data->hostname, __type);
	if (ret < 0) {
		const char *ret_str;

		ret_str = inet_ntop(__type, __addr, __buf, __buflen);
		if (!ret_str) {
			ret = HOST_NOT_FOUND;
			if (errno == ENOSPC) {
				ret = ERANGE;
			}
			if (__h_errnop) {
				*__h_errnop = HOST_NOT_FOUND;
			}
			goto error;
		}
	}

	/* Ease our life a bit. */
	he = __ret;

	if (!he) {
		ret = NO_RECOVERY;
		if (__h_errnop) {
			*__h_errnop = NO_RECOVERY;
		}
		goto error;
	}

	if (data->hostname) {
		he->h_name = data->hostname;
	} else {
		ret = NO_RECOVERY;
		if (__h_errnop) {
			*__h_errnop = NO_RECOVERY;
		}
		goto error;
	}

	he->h_aliases = NULL;
	he->h_length = strlen(he->h_name);
	/* Assign the address list within the data of the given buffer. */
	data->addr_list[0] = (char *) __addr;
	data->addr_list[1] = NULL;
	he->h_addr_list = data->addr_list;

	if (__result) {
		*__result = he;
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

	DBG("[gethostbyname_r] Requesting %s hostname", __name);

	if (!__name) {
		*__h_errnop = HOST_NOT_FOUND;
		ret = -1;
		goto error;
	}

	if (__buflen < sizeof(*data)) {
		ret = ERANGE;
		goto error;
	}

	/* Resolve the given hostname through Tor. */
	ret = tsocks_tor_resolve(__name, &ip);
	if (ret < 0) {
		goto error;
	}

	data = (struct data *) __buf;
	memset(data, 0, sizeof(*data));
	/* Ease our life a bit. */
	he = __ret;

	ret_str = inet_ntop(AF_INET, &ip, data->addr, sizeof(data->addr));
	if (!ret_str) {
		PERROR("inet_ntop");
		*__h_errnop = NO_ADDRESS;
		goto error;
	}

	memcpy(data->addr, &ip, sizeof(ip));
	data->addr_list[0] = data->addr;
	data->addr_list[1] = NULL;
	he->h_addr_list = data->addr_list;

	he->h_name = (char *) __name;
	he->h_aliases = NULL;
	he->h_length = sizeof(in_addr_t);
	he->h_addrtype = AF_INET;

	DBG("[gethostbyname_r] Hostname %s resolved to %s", __name,
			inet_ntoa(*((struct in_addr *) &ip)));

error:
	return ret;
}

/*
 * Libc hijacked symbol gethostbyname_r(3).
 */
LIBC_GETHOSTBYNAME_R_DECL
{
	return tsocks_gethostbyname_r(LIBC_GETHOSTBYNAME_R_ARGS);
}

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: GNU extension. Reentrant version.
 */
LIBC_GETHOSTBYNAME2_R_RET_TYPE tsocks_gethostbyname2_r(LIBC_GETHOSTBYNAME2_R_SIG)
{
	DBG("[gethostbyname2_r] Requesting %s hostname", __name);

	/*
	 * For now, there is no way of resolving a domain name to IPv6 through Tor
	 * so only accept INET request thus using the original gethostbyname().
	 */
	if (__af != AF_INET) {
		*__h_errnop = HOST_NOT_FOUND;
		return -1;
	}

	return tsocks_gethostbyname_r(__name, __ret, __buf, __buflen, __result,
			__h_errnop);
}

/*
 * Libc hijacked symbol gethostbyname2_r(3).
 */
LIBC_GETHOSTBYNAME2_R_DECL
{
	return tsocks_gethostbyname2_r(LIBC_GETHOSTBYNAME2_R_ARGS);
}
