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

/* socket(2) */
TSOCKS_LIBC_DECL(socket, LIBC_SOCKET_RET_TYPE, LIBC_SOCKET_SIG)

/*
 * Torsocks call for socket(2)
 */
LIBC_SOCKET_RET_TYPE tsocks_socket(LIBC_SOCKET_SIG)
{
	DBG("[socket] Creating socket with domain %d, type %d and protocol %d",
			domain, type, protocol);

	if (IS_SOCK_STREAM(type)) {
		/*
		 * The socket family is not checked here since we accept local socket
		 * (AF_UNIX) that can NOT do outbound traffic.
		 */
		goto end;
	} else {
		/*
		 * Non INET[6] socket can't be handle by tor else create the socket.
		 * The connect function will deny anything that Tor can NOT handle.
		 */
		if (domain != AF_INET && domain != AF_INET6) {
			goto end;
		}

		/*
		 * Print this message only in debug mode. Very often, applications uses
		 * the libc to do DNS resolution which first tries with UDP and then
		 * with TCP. It's not critical for the user to know that a non TCP
		 * socket has been denied and since the libc has a fallback that works,
		 * this message most of the time, simply polutes the application's
		 * output which can cause issues with external applications parsing the
		 * output.
		 */
		DBG("IPv4/v6 non TCP socket denied. Tor network can't handle it.");
		errno = EPERM;
		return -1;

	}

end:
	/* Stream socket for INET/INET6 is good so open it. */
	return tsocks_libc_socket(domain, type, protocol);
}

/*
 * Libc hijacked symbol socket(2).
 */
LIBC_SOCKET_DECL
{
	if (!tsocks_libc_socket)
		tsocks_initialize();
	return tsocks_socket(LIBC_SOCKET_ARGS);
}
