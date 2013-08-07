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
#include <stdarg.h>

#include <common/log.h>

#include "torsocks.h"

/*
 * Handle close syscall to be called with tsocks call.
 */
static LIBC_CLOSE_RET_TYPE handle_close(va_list args)
{
	int fd;

	fd = va_arg(args, int);

	return tsocks_close(fd);
}

/*
 * Handle socket syscall to go through Tor.
 */
static LIBC_SOCKET_RET_TYPE handle_socket(va_list args)
{
	int domain, type, protocol;

	domain = va_arg(args, int);
	type = va_arg(args, int);
	protocol = va_arg(args, int);

	return tsocks_socket(domain, type, protocol);
}

/*
 * Handle connect syscall to go through Tor.
 */
static LIBC_CONNECT_RET_TYPE handle_connect(va_list args)
{
	int sockfd;
	const struct sockaddr *addr;
	socklen_t addrlen;

	sockfd = va_arg(args, int);
	addr = va_arg(args, const struct sockaddr *);
	addrlen = va_arg(args, socklen_t);

	return tsocks_connect(sockfd, addr, addrlen);
}

/*
 * Torsocks call for syscall(2)
 */
LIBC_SYSCALL_RET_TYPE tsocks_syscall(long int __number, va_list args)
{
	long int ret;

	DBG("[syscall] Syscall libc wrapper number %ld called", __number);

	switch (__number) {
	case __NR_socket:
		ret = handle_socket(args);
		break;
	case __NR_connect:
		ret = handle_connect(args);
		break;
	case __NR_close:
		ret = handle_close(args);
		break;
	default:
		ret = tsocks_libc_syscall(__number, args);
		break;
	}

	return ret;
}

/*
 * Libc hijacked symbol syscall(2).
 */
LIBC_SYSCALL_DECL
{
	LIBC_SYSCALL_RET_TYPE ret;
	va_list args;

	/* Find symbol if not already set. Exit if not found. */
	tsocks_libc_syscall = tsocks_find_libc_symbol(LIBC_SYSCALL_NAME_STR,
			TSOCKS_SYM_EXIT_NOT_FOUND);

	va_start(args, __number);
	ret = tsocks_syscall(__number, args);
	va_end(args);

	return ret;
}
