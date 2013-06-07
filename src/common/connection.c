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

#include "connection.h"

/*
 * Create a new connection with the given fd and destination address.
 *
 * Return a newly allocated connection object or else NULL.
 */
struct connection *connection_create(int fd, struct sockaddr_in *dest)
{
	struct connection *conn;

	assert(dest);

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc connection");
		goto error;
	}

	conn->fd = fd;
	memcpy(conn->dest_addr, dest, sizeof(conn->dest_addr));

	return conn;

error:
	return NULL;
}

/*
 * Destroy a connection by freeing its memory.
 */
void connection_destroy(struct connection *conn)
{
	if (!conn) {
		return;
	}

	/* Remove from the double linked list. */
	conn->prev->next = conn->next;
	conn->next->prev = conn->prev;

	free(conn);
}
