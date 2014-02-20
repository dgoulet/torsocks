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
 * Connection registry mutex.
 *
 * MUST be acquired for each read/write operation on the connection registry
 * declared below.
 *
 * This mutex is NOT nested anywhere.
 */
static TSOCKS_INIT_MUTEX(connection_registry_mutex);

/*
 * Release connection using the given refcount located inside the connection
 * object. This is ONLY called from the connection put reference. After this
 * call, the connection object associated with that refcount object is freed.
 */
static void release_conn(struct ref *ref)
{
	struct connection *conn = container_of(ref, struct connection, refcount);
	connection_destroy(conn);
}

/*
 * Return 0 if the two connections are equal else 1.
 */
static inline int conn_equal_fct(struct connection *c1,
		struct connection *c2)
{
	return (c1->fd == c2->fd);
}

/*
 * Return a hash value based on the unique fd of the given connection.
 */
static inline unsigned int conn_hash_fct(struct connection *c)
{
	unsigned int mask;

	assert(c);

	switch (sizeof(mask)) {
	case 1:
		mask = 0xff;
		break;
	case 2:
		mask = 0xffff;
		break;
	case 4:
	default:
		mask = 0xffffffff;
		break;
	}

	return (((unsigned int)(c->fd) << 8) ^
				((unsigned int)((c->fd >> sizeof(mask)) & mask)) ^
				((unsigned int)(c->fd & mask)));
}

/*
 * Declare the connection registry.
 */
static HT_HEAD(connection_registry, connection) connection_registry_root;
HT_PROTOTYPE(connection_registry, connection, node, conn_hash_fct,
		conn_equal_fct);
HT_GENERATE(connection_registry, connection, node, conn_hash_fct,
		conn_equal_fct, 0.5, malloc, realloc, free);

/*
 * Acquire connection registry mutex.
 */
ATTR_HIDDEN
void connection_registry_lock(void)
{
	tsocks_mutex_lock(&connection_registry_mutex);
}

/*
 * Release connection registry mutex.
 */
ATTR_HIDDEN
void connection_registry_unlock(void)
{
	tsocks_mutex_unlock(&connection_registry_mutex);
}

/*
 * Initialize connection registry.
 */
ATTR_HIDDEN
void connection_registry_init(void)
{
	HT_INIT(connection_registry, &connection_registry_root);
}

/*
 * Set an already allocated connection address using the given IPv4/6 address,
 * domain and port.
 *
 * Return 0 on success or else a negative value.
 */
ATTR_HIDDEN
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
ATTR_HIDDEN
struct connection *connection_create(int fd, const struct sockaddr *dest)
{
	struct connection *conn = NULL;

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc connection");
		goto error;
	}

	if (dest) {
		switch (dest->sa_family) {
		case AF_INET:
			conn->dest_addr.domain = CONNECTION_DOMAIN_INET;
			memcpy(&conn->dest_addr.u.sin, dest,
					sizeof(conn->dest_addr.u.sin));
			break;
		case AF_INET6:
			conn->dest_addr.domain = CONNECTION_DOMAIN_INET6;
			memcpy(&conn->dest_addr.u.sin6, dest,
					sizeof(conn->dest_addr.u.sin6));
			break;
		default:
			ERR("Connection domain unknown %d", dest->sa_family);
			goto error;
		}
	}

	conn->fd = fd;
	connection_get_ref(conn);

	return conn;

error:
	free(conn);
	return NULL;
}

/*
 * Return the matching element with the given key or NULL if not found.
 */
ATTR_HIDDEN
struct connection *connection_find(int key)
{
	struct connection c_tmp;

	c_tmp.fd = key;
	return HT_FIND(connection_registry, &connection_registry_root, &c_tmp);
}

/*
 * Insert a connection object into the hash table.
 */
ATTR_HIDDEN
void connection_insert(struct connection *conn)
{
	struct connection *c_tmp;

	assert(conn);

	/* An existing element is a code flow error. */
	c_tmp = connection_find(conn->fd);
	assert(!c_tmp);

	HT_INSERT(connection_registry, &connection_registry_root, conn);
}

/*
 * Remove a given connection object from the registry.
 */
ATTR_HIDDEN
void connection_remove(struct connection *conn)
{
	assert(conn);
	HT_REMOVE(connection_registry, &connection_registry_root, conn);
}

/*
 * Destroy a connection by freeing its memory.
 */
ATTR_HIDDEN
void connection_destroy(struct connection *conn)
{
	if (!conn) {
		return;
	}

	free(conn->dest_addr.hostname.addr);
	free(conn);
}

/*
 * Get a reference of the given connection object.
 */
ATTR_HIDDEN
void connection_get_ref(struct connection *c)
{
	ref_get(&c->refcount);
}

/*
 * Put back a reference of the given connection object. If the refcount drops
 * to 0, the release connection function is called which frees the object.
 */
ATTR_HIDDEN
void connection_put_ref(struct connection *c)
{
	ref_put(&c->refcount, release_conn);
}
