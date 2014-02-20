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

TSOCKS_LIBC_DECL(listen, LIBC_LISTEN_RET_TYPE, LIBC_LISTEN_SIG)

/*
 * Torsocks call for listen(2).
 */
LIBC_LISTEN_RET_TYPE tsocks_listen(LIBC_LISTEN_SIG)
{
	DBG("[accept] Syscall denied since inbound connection are not allowed.");

	/*
	 * Bind is completely denied here since this means that the application
	 * can accept inbound connections that are obviously NOT handled by the Tor
	 * network thus reject this call.
	 */
	errno = EPERM;
	return -1;
}

/*
 * Libc hijacked symbol listen(2).
 */
LIBC_LISTEN_DECL
{
	return tsocks_listen(LIBC_LISTEN_ARGS);
}
