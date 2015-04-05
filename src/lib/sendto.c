/*
 * Copyright (C) 2015 - Tim Rühsen <tim.ruehsen@gmx.de>
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
#include <common/utils.h>

#include "torsocks.h"

/*
 * Using TCP Fast Open (TFO) uses sendto() instead of connect() with 'flags'
 * set to MSG_FASTOPEN. Without this code, using TFO simply bypasses Tor
 * without letting the user know.
 *
 * This solution simply ignores TFO and falls back to connect(). At the time
 * the tor server supports TFO, socks5.c (client code) could implement it in
 * send_data() and connect_socks5().
 */

/* sendto(2)
 * args: int sockfd, const void *buf, size_t len, int flags,
 *       const struct sockaddr *dest_addr, socklen_t addrlen
 */
TSOCKS_LIBC_DECL(sendto, LIBC_SENDTO_RET_TYPE, LIBC_SENDTO_SIG)

/*
 * Torsocks call for sendto(2).
 */
LIBC_SENDTO_RET_TYPE tsocks_sendto(LIBC_SENDTO_SIG)
{
#ifdef MSG_FASTOPEN
	int ret;

	if ((flags & MSG_FASTOPEN) == 0) {
		/* No TFO, fallback to libc sendto() */
		goto libc_sendto;
	}

	DBG("[sendto] TCP fast open catched on fd %d", sockfd);

	ret = connect(sockfd, dest_addr, addrlen);
	if (ret == 0) {
		/* Connection established, send payload */
		ret = send(sockfd, buf, len, flags & ~MSG_FASTOPEN);
	}

	return ret;

libc_sendto:
#endif /* MSG_FASTOPEN */

	return tsocks_libc_sendto(LIBC_SENDTO_ARGS);
}

/*
 * Libc hijacked symbol sendto(2).
 */
LIBC_SENDTO_DECL
{
	if (!tsocks_libc_sendto) {
		tsocks_initialize();
		tsocks_libc_sendto = tsocks_find_libc_symbol(
				LIBC_SENDTO_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_sendto(LIBC_SENDTO_ARGS);
}
