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

#include <common/connection.h>
#include <common/log.h>

#include "torsocks.h"

/* close(2) */
TSOCKS_LIBC_DECL(close, LIBC_CLOSE_RET_TYPE, LIBC_CLOSE_SIG)

/*
 * Torsocks call for close(2).
 */
LIBC_CLOSE_RET_TYPE tsocks_close(LIBC_CLOSE_SIG)
{
	struct connection *conn;

	DBG("Close catched for fd %d", fd);

	connection_registry_lock();
	conn = connection_find(fd);
	if (conn) {
		/*
		 * Remove from the registry so it's not visible anymore and thus using
		 * it without lock.
		 */
		connection_remove(conn);
	}
	connection_registry_unlock();

	/*
	 * Put back the connection reference. If the refcount get to 0, the
	 * connection pointer is destroyed.
	 */
	if (conn) {
		DBG("Close connection putting back ref");
		connection_put_ref(conn);
	}

	/* Return the original libc close. */
	return tsocks_libc_close(fd);
}

/*
 * Libc hijacked symbol close(2).
 */
LIBC_CLOSE_DECL
{
	return tsocks_close(LIBC_CLOSE_ARGS);
}
