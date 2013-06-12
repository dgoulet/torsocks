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

#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>

#include "connection.h"
#include "macros.h"

/*
 * Set an already allocated connection address using the given IPv4/6 address,
 * domain and port.
 *
 * Return 0 on success or else a negative value.
 */
int connection_addr_set(enum connection_domain domain, const char *ip,
		in_port_t port, struct connection_addr *addr)
{
	int ret;

	assert(ip);
	assert(addr);

	if (port == 0 || port >= 65535) {
		ret = -EINVAL;
		ERR("Connection addr set port out of range: %d", port);
		goto error;
	}

	memset(addr, 0, sizeof(*addr));

	switch (domain) {
	case CONNECTION_DOMAIN_INET:
		addr->domain = domain;
		addr->u.sin.sin_family = AF_INET;
		addr->u.sin.sin_port = htons(port);
		ret = inet_pton(addr->u.sin.sin_family, ip,
				&addr->u.sin.sin_addr);
		if (ret != 1) {
			PERROR("Connection addr set inet_pton");
			ret = -EINVAL;
			goto error;
		}
		break;
	case CONNECTION_DOMAIN_INET6:
		addr->domain = domain;
		addr->u.sin6.sin6_family = AF_INET6;
		addr->u.sin6.sin6_port = htons(port);
		ret = inet_pton(addr->u.sin6.sin6_family, ip,
				&addr->u.sin6.sin6_addr);
		if (ret != 1) {
			PERROR("Connection addr6 set inet_pton");
			ret = -EINVAL;
			goto error;
		}
		break;
	default:
		ERR("Connection addr set unknown domain %d", domain);
		ret = -EINVAL;
		goto error;
	}

	/* Everything is set and good. */
	ret = 0;

error:
	return ret;
}

/*
 * Create a new connection with the given fd and destination address.
 *
 * Return a newly allocated connection object or else NULL.
 */
struct connection *connection_create(int fd, enum connection_domain domain,
		struct sockaddr *dest)
{
	struct connection *conn = NULL;

	assert(dest);

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc connection");
		goto error;
	}

	switch (domain) {
	case CONNECTION_DOMAIN_INET:
		memcpy(&conn->dest_addr.u.sin, dest, sizeof(conn->dest_addr.u.sin));
		break;
	case CONNECTION_DOMAIN_INET6:
		memcpy(&conn->dest_addr.u.sin6, dest, sizeof(conn->dest_addr.u.sin6));
		break;
	default:
		ERR("Connection domain unknown %d", domain);
		goto error;
	}

	conn->fd = fd;

	return conn;

error:
	free(conn);
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
	if (conn->prev) {
		conn->prev->next = conn->next;
	}

	if (conn->next) {
		conn->next->prev = conn->prev;
	}

	free(conn);
}
