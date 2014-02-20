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

#include "torsocks.h"

TSOCKS_LIBC_DECL(accept, LIBC_ACCEPT_RET_TYPE, LIBC_ACCEPT_SIG)

/*
 * Torsocks call for accept(2).
 */
LIBC_ACCEPT_RET_TYPE tsocks_accept(LIBC_ACCEPT_SIG)
{
	DBG("[accept] Syscall denied since inbound connection are not allowed.");

	/*
	 * Accept is completely denied here since this means that the application
	 * can accept inbound connections that are obviously NOT handled by the Tor
	 * network thus reject this call.
	 */
	errno = EPERM;
	return -1;
}

/*
 * Libc hijacked symbol accept(2).
 */
LIBC_ACCEPT_DECL
{
	return tsocks_accept(LIBC_ACCEPT_ARGS);
}

#if (defined(__linux__))

TSOCKS_LIBC_DECL(accept4, LIBC_ACCEPT4_RET_TYPE, LIBC_ACCEPT4_SIG)

/*
 * Torsocks call for accept4(2).
 */
LIBC_ACCEPT4_RET_TYPE tsocks_accept4(LIBC_ACCEPT4_SIG)
{
	DBG("[accept] Syscall denied since inbound connection are not allowed.");

	/*
	 * Accept is completely denied here since this means that the application
	 * can accept inbound connections that are obviously NOT handled by the Tor
	 * network thus reject this call.
	 */
	errno = EPERM;
	return -1;
}

/*
 * Libc hijacked symbol accept4(2).
 */
LIBC_ACCEPT4_DECL
{
	return tsocks_accept4(LIBC_ACCEPT4_ARGS);
}
#endif
