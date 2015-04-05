/*
 * Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
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

#include <common/utils.h>

#include "torsocks.h"

TSOCKS_LIBC_DECL(listen, LIBC_LISTEN_RET_TYPE, LIBC_LISTEN_SIG)

/*
 * Torsocks call for listen(2).
 */
LIBC_LISTEN_RET_TYPE tsocks_listen(LIBC_LISTEN_SIG)
{
	int ret;
	socklen_t addrlen;
	struct sockaddr sa;

	if (tsocks_config.allow_inbound) {
		/* Allowed by the user so directly go to the libc. */
		goto libc_call;
	}

	addrlen = sizeof(sa);

	ret = getsockname(sockfd, &sa, &addrlen);
	if (ret < 0) {
		PERROR("[listen] getsockname");
		goto error;
	}

	/*
	 * Listen () on a Unix socket is allowed else we are going to try to match
	 * it on INET localhost socket.
	 */
	if (sa.sa_family == AF_UNIX) {
		goto libc_call;
	}

	/* Inbound localhost connections are allowed. */
	ret = utils_sockaddr_is_localhost(&sa);
	if (!ret) {
		/*
		 * Listen is completely denied here since this means that the
		 * application can accept inbound connections on non localhost that are
		 * obviously NOT handled by the Tor network thus reject this call.
		 */
		DBG("[listen] Non localhost inbound connection are not allowed.");
		errno = EPERM;
		goto error;
	}

libc_call:
	DBG("[listen] Passing listen fd %d to libc", sockfd);
	return tsocks_libc_listen(LIBC_LISTEN_ARGS);

error:
	return -1;
}

/*
 * Libc hijacked symbol listen(2).
 */
LIBC_LISTEN_DECL
{
	if (!tsocks_libc_listen) {
		tsocks_initialize();
		tsocks_libc_listen = tsocks_find_libc_symbol(
				LIBC_LISTEN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_listen(LIBC_LISTEN_ARGS);
}
