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

#include <arpa/inet.h>
#include <assert.h>

#include <common/log.h>

#include "torsocks.h"

/* getpeername(2) */
TSOCKS_LIBC_DECL(getpeername, LIBC_GETPEERNAME_RET_TYPE,
		LIBC_GETPEERNAME_SIG)

/*
 * Torsocks call for getpeername(2).
 */
LIBC_GETPEERNAME_RET_TYPE tsocks_getpeername(LIBC_GETPEERNAME_SIG)
{
	int ret = 0;
	struct connection *conn;

	DBG("[getpeername] Requesting address on socket %d", __sockfd);

	connection_registry_lock();
	conn = connection_find(__sockfd);
	if (!conn) {
		errno = ENOTCONN;
		ret = -1;
		goto end;
	}
	connection_registry_unlock();

	errno = 0;
end:
	return ret;
}

/*
 * Libc hijacked symbol getpeername(2).
 */
LIBC_GETPEERNAME_DECL
{
	int ret;

	tsocks_libc_getpeername = tsocks_find_libc_symbol(LIBC_GETPEERNAME_NAME_STR,
			TSOCKS_SYM_EXIT_NOT_FOUND);

	ret = tsocks_libc_getpeername(LIBC_GETPEERNAME_ARGS);
	if (ret < 0) {
		/* errno is populated by the previous call at this point. */
		return ret;
	}

	return tsocks_getpeername(LIBC_GETPEERNAME_ARGS);
}
