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

#include <common/connection.h>
#include <common/log.h>

#include "torsocks.h"

/* fclose(3) */
TSOCKS_LIBC_DECL(fclose, LIBC_FCLOSE_RET_TYPE, LIBC_FCLOSE_SIG)

/*
 * Torsocks call for fclose(3).
 */
LIBC_FCLOSE_RET_TYPE tsocks_fclose(LIBC_FCLOSE_SIG)
{
	int fd;
	struct connection *conn;

	if (!fp) {
		errno = EBADF;
		goto error;
	}

	fd = fileno(fp);
	if (fd < 0) {
		/* errno is set to EBADF here by fileno(). */
		goto error;
	}

	DBG("[fclose] Close catched for fd %d", fd);

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

	/* Return the original libc fclose. */
	return tsocks_libc_fclose(fp);

error:
	return -1;
}

/*
 * Libc hijacked symbol fclose(3).
 */
LIBC_FCLOSE_DECL
{
	if (!tsocks_libc_fclose) {
		tsocks_libc_fclose = tsocks_find_libc_symbol(
				LIBC_FCLOSE_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_fclose(LIBC_FCLOSE_ARGS);
}
