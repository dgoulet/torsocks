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

TSOCKS_LIBC_DECL(bind, LIBC_BIND_RET_TYPE, LIBC_BIND_SIG)

/*
 * Torsocks call for bind(2).
 */
LIBC_BIND_RET_TYPE tsocks_bind(LIBC_BIND_SIG)
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
 * Libc hijacked symbol bind(2).
 */
LIBC_BIND_DECL
{
	return tsocks_bind(LIBC_BIND_ARGS);
}
