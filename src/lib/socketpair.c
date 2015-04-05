/*
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

#include <assert.h>

#include <common/log.h>

#include "torsocks.h"

/* socketpair(2) */
TSOCKS_LIBC_DECL(socketpair, LIBC_SOCKETPAIR_RET_TYPE, LIBC_SOCKETPAIR_SIG)

/*
 * Torsocks call for socketpair(2)
 */
LIBC_SOCKETPAIR_RET_TYPE tsocks_socketpair(LIBC_SOCKETPAIR_SIG)
{
	DBG("[socketpair] Creating socket with domain %d, type %d and protocol %d",
			domain, type, protocol);

	if (domain == AF_INET || domain == AF_INET6) {
		DBG("Non TCP socketpair denied. Tor network can't handle it.");
		errno = EPERM;
		return -1;
	}

	/* Stream socket for INET/INET6 is good so open it. */
	return tsocks_libc_socketpair(domain, type, protocol, sv);
}

/*
 * Libc hijacked symbol socketpair(2).
 */
LIBC_SOCKETPAIR_DECL
{
	if (!tsocks_libc_socketpair) {
		tsocks_initialize();
		tsocks_libc_socketpair = tsocks_find_libc_symbol(
				LIBC_SOCKETPAIR_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_socketpair(LIBC_SOCKETPAIR_ARGS);
}
