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

#ifndef TORSOCKS_ONION_H
#define TORSOCKS_ONION_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat.h"
#include "macros.h"	/* zmalloc */

/*
 * Onion entry in the pool. This is to map a cookie IP to an .onion address in
 * the connect() process.
 */
struct onion_entry {
	/*
	 * It's always an IPv4 which is taken from the onion IP range.
	 */
	in_addr_t ip;

	/*
	 * Maximum host name length plus one for the NULL terminated byte.
	 */
	char hostname[256];
};

/*
 * For .onion address representing an address to a hidden service, a "cookie"
 * is used during DNS resolution which represents a specific dead IP address
 * that is not routable on the Internet. This cookie is returned to the caller
 * and once a connect arrives with an address being a cookie, the connection to
 * Tor is done using the corresponding onion address.
 *
 * This object MUST be accessed and modified inside the torsocks registry lock
 * to avoid cookie allocation race. Once an entry object reference is acquired,
 * the lock can be released since the object is immutable.
 */
struct onion_pool {
	/*
	 * Subnet used for the cookie address.
	 */
	in_addr_t ip_subnet;

	/*
	 * Protects every lookup and insertion in this pool object.
	 *
	 * This is nested INSIDE the connection registry lock.
	 */
	tsocks_mutex_t lock;

	/* Number of valid entry in the pool. */
	uint32_t count;

	/*
	 * Starting base of available cookie. For a range of 127.0.69.64/26, this
	 * base value would be 64 and the max value in this case is 127.
	 *
	 * If the maxium value is reached, the DNS resolution will fail thus never
	 * returning any cookie to the caller.
	 */
	uint32_t base;
	uint32_t max_pos;

	/*
	 * Current size of the array. This is the number of allocated entry in the
	 * pool which does not represent the number of entry.
	 */
	uint32_t size;

	/*
	 * This is the next available entry position. Once the onion entry is added
	 * to the pool, this counter is incremented. If the pool needs to be
	 * resized, a reallocation is done and size is updated accordingly.
	 */
	uint32_t next_entry_pos;

	/*
	 * Array of onion entry indexed by cookie position. For instance, using the
	 * IP range 127.0.69.0/24, the array is of maximum size 255 and address
	 * 127.0.69.32 points to the 32th position in the array.
	 */
	struct onion_entry **entries;
};

/*
 * Destroy an onion entry object.
 */
static inline void onion_entry_destroy(struct onion_entry *entry)
{
	free(entry);
}

/* Onion entry family functions. */
struct onion_entry *onion_entry_create(struct onion_pool *pool,
		const char *onion_name);
struct onion_entry *onion_entry_find_by_name(const char *onion_name,
		struct onion_pool *pool);
struct onion_entry *onion_entry_find_by_addr(const struct sockaddr *sa,
		struct onion_pool *pool);

static inline void onion_pool_lock(struct onion_pool *pool)
{
	tsocks_mutex_lock(&pool->lock);
}

static inline void onion_pool_unlock(struct onion_pool *pool)
{
	tsocks_mutex_unlock(&pool->lock);
}

/*
 * Onion pool function calls.
 */
int onion_pool_init(struct onion_pool *pool, in_addr_t base, uint8_t mask);
void onion_pool_destroy(struct onion_pool *pool);

#endif /* TORSOCKS_ONION_H */
