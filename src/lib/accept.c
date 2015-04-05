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

TSOCKS_LIBC_DECL(accept, LIBC_ACCEPT_RET_TYPE, LIBC_ACCEPT_SIG)

/*
 * Torsocks call for accept(2).
 */
LIBC_ACCEPT_RET_TYPE tsocks_accept(LIBC_ACCEPT_SIG)
{
	int ret;
	socklen_t sa_len;
	struct sockaddr sa;

	if (tsocks_config.allow_inbound) {
		/* Allowed by the user so directly go to the libc. */
		goto libc_call;
	}

	if (!addr) {
		errno = EFAULT;
		goto error;
	}

	sa_len = sizeof(sa);

	ret = getsockname(sockfd, &sa, &sa_len);
	if (ret < 0) {
		PERROR("[accept] getsockname");
		goto error;
	}

	/*
	 * accept() on a Unix socket is allowed else we are going to try to match
	 * it on INET localhost socket.
	 */
	if (sa.sa_family == AF_UNIX) {
		goto libc_call;
	}

	/* Inbound localhost connections are allowed. */
	ret = utils_sockaddr_is_localhost(&sa);
	if (!ret) {

		/*
		 * Accept is completely denied here since this means that the
		 * application can accept inbound connections on non localhost that are
		 * obviously NOT handled by the Tor network thus reject this call.
		 */
		DBG("[accept] Non localhost inbound connection are not allowed.");
		errno = EPERM;
		goto error;
	}

libc_call:
	return tsocks_libc_accept(LIBC_ACCEPT_ARGS);

error:
	return -1;
}

/*
 * Libc hijacked symbol accept(2).
 */
LIBC_ACCEPT_DECL
{
	if (!tsocks_libc_accept) {
		tsocks_initialize();
		tsocks_libc_accept = tsocks_find_libc_symbol(
				LIBC_ACCEPT_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_accept(LIBC_ACCEPT_ARGS);
}

#if (defined(__linux__))

TSOCKS_LIBC_DECL(accept4, LIBC_ACCEPT4_RET_TYPE, LIBC_ACCEPT4_SIG)

/*
 * Torsocks call for accept4(2).
 */
LIBC_ACCEPT4_RET_TYPE tsocks_accept4(LIBC_ACCEPT4_SIG)
{
	int ret;
	socklen_t sa_len;
	struct sockaddr sa;

	if (tsocks_config.allow_inbound) {
		/* Allowed by the user so directly go to the libc. */
		goto libc_call;
	}

	if (!addr) {
		errno = EFAULT;
		goto error;
	}

	sa_len = sizeof(sa);

	ret = getsockname(sockfd, &sa, &sa_len);
	if (ret < 0) {
		PERROR("[accept4] getsockname");
		goto error;
	}

	/*
	 * accept4() on a Unix socket is allowed else we are going to try to match
	 * it on INET localhost socket.
	 */
	if (sa.sa_family == AF_UNIX) {
		goto libc_call;
	}

	/* Inbound localhost connections are allowed. */
	ret = utils_sockaddr_is_localhost(&sa);
	if (!ret) {

		/*
		 * Accept is completely denied here since this means that the
		 * application can accept inbound connections on non localhost that are
		 * obviously NOT handled by the Tor network thus reject this call.
		 */
		DBG("[accept4] Non localhost inbound connection are not allowed.");
		errno = EPERM;
		goto error;
	}

libc_call:
	return tsocks_libc_accept4(LIBC_ACCEPT4_ARGS);

error:
	return -1;
}

/*
 * Libc hijacked symbol accept4(2).
 */
LIBC_ACCEPT4_DECL
{
	if (!tsocks_libc_accept4) {
		tsocks_initialize();
		tsocks_libc_accept4 = tsocks_find_libc_symbol(
				LIBC_ACCEPT4_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_accept4(LIBC_ACCEPT4_ARGS);
}
#endif
