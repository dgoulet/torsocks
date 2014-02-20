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

#include "defaults.h"
#include "log.h"
#include "onion.h"

/*
 * Resize pool entries of new_size.
 *
 * Return 0 on success or else -1.
 */
static int resize_onion_pool(struct onion_pool *pool, uint32_t new_size)
{
	struct onion_entry **tmp;

	assert(new_size > pool->size);

	tmp = realloc(pool->entries, new_size * sizeof(*tmp));
	if (!tmp) {
		PERROR("[onion] resize onion pool");
		goto error;
	}

	DBG("[onion] Onion pool resized from size %lu to new size %lu", pool->size,
			new_size);

	pool->entries = tmp;
	pool->size = new_size;
	return 0;

error:
	return -1;
}

/*
 * Insert an onion entry in the given pool.
 *
 * Return 0 on success or else a negative value.
 */
static int insert_onion_entry(struct onion_entry *entry,
		struct onion_pool *pool)
{
	int ret;

	assert(entry);
	assert(pool);

	if (pool->count > pool->size) {
		/* Double the size of the pool. */
		ret = resize_onion_pool(pool, pool->size * 2);
		if (ret < 0) {
			goto error;
		}
	}

	pool->entries[pool->next_entry_pos] = entry;
	pool->next_entry_pos++;
	pool->count++;
	ret = 0;

	DBG("[onion] Entry added to the onion pool at index %lu",
			pool->next_entry_pos - 1);

error:
	return ret;
}

/*
 * Initialize an already allocated onion pool using the given values.
 *
 * Return 0 on success or else a negative value.
 */
ATTR_HIDDEN
int onion_pool_init(struct onion_pool *pool, in_addr_t addr, uint8_t mask)
{
	int ret = 0;

	assert(pool);

	if (mask == 0 || mask > 32) {
		ERR("[onion] Pool initialized with mask set to %u.", mask);
		ret = -EINVAL;
		goto error;
	}

	DBG("[onion] Pool init with subnet %s and mask %u",
			inet_ntoa(*((struct in_addr *) &addr)), mask);

	/*
	 * Get base of subnet. For example, 127.0.0.68/27 will set the base to 64
	 * and the max_pos to 95.
	 */
	pool->base = (((ntohl(addr) >> (32 - mask)) << (32 - mask)) << 24) >> 24;
	pool->max_pos = pool->base + ((1UL << (32 - mask)) - 1);
	pool->next_entry_pos = 0;
	pool->count = 0;
	tsocks_mutex_init(&pool->lock);

	/*
	 * Get the minimum value between the two to avoid allocating more memory
	 * than we need.
	 */
	pool->size = min(DEFAULT_ONION_POOL_SIZE, (pool->max_pos - pool->base) + 1);

	memcpy(&pool->ip_subnet, &addr, sizeof(pool->ip_subnet));

	pool->entries = zmalloc(sizeof(struct onion_entry *) * pool->size);
	if (!pool->entries) {
		PERROR("[onion] zmalloc pool init");
		ret = -ENOMEM;
		goto error;
	}

	DBG("[onion] Pool initialized with base %lu, max_pos %lu and size %lu",
			pool->base, pool->max_pos, pool->size);

error:
	return ret;
}

/*
 * Destroy onion pool by freeing every entry.
 */
ATTR_HIDDEN
void onion_pool_destroy(struct onion_pool *pool)
{
	int i;

	assert(pool);

	DBG("[onion] Destroying onion pool containing %u entry", pool->count);

	for (i = 0; i < pool->count; i++) {
		onion_entry_destroy(pool->entries[i]);
	}

	free(pool->entries);
}

/*
 * Allocate an onion entry object and return the pointer. This MUST be called
 * with the onion pool lock acquired.
 *
 * Return a newly allocated onion entry or else NULL.
 */
ATTR_HIDDEN
struct onion_entry *onion_entry_create(struct onion_pool *pool,
		const char *onion_name)
{
	int ret;
	uint32_t ip_host_order;
	struct onion_entry *entry = NULL;

	assert(pool);
	assert(onion_name);

	DBG("[onion] Creating onion entry for name %s", onion_name);

	if (pool->next_entry_pos == pool->max_pos) {
		ERR("[onion] Can't create anymore onion entry. Maximum reached (%u)",
				pool->max_pos);
		goto error;
	}

	entry = zmalloc(sizeof(struct onion_entry));
	if (!entry) {
		PERROR("[onion] zmalloc entry");
		goto error;
	}

	/* Copy hostname and force NULL byte at the end. */
	strncpy(entry->hostname, onion_name, sizeof(entry->hostname));
	entry->hostname[sizeof(entry->hostname) - 1] = '\0';

	/*
	 * Create the new IP from the onion pool which will be the cookie returned
	 * to the caller.
	 */
	ip_host_order = ntohl(pool->ip_subnet) + pool->next_entry_pos;
	entry->ip = htonl(ip_host_order);

	ret = insert_onion_entry(entry, pool);
	if (ret < 0) {
		onion_entry_destroy(entry);
		entry = NULL;
		goto error;
	}

	DBG("[onion] Entry added with IP address %s used as cookie",
			inet_ntoa(*((struct in_addr *) &entry->ip)));

error:
	return entry;
}

/*
 * Find an onion entry by onion address name. The pool lock MUST be acquired
 * before calling this.
 *
 * Return entry on success or else NULL.
 */
ATTR_HIDDEN
struct onion_entry *onion_entry_find_by_name(const char *onion_name,
		struct onion_pool *pool)
{
	int i;
	struct onion_entry *entry = NULL;

	assert(onion_name);
	assert(pool);

	DBG("[onion] Finding onion entry for name %s", onion_name);

	for (i = 0; i < pool->count; i++) {
		if (strcmp(onion_name, pool->entries[i]->hostname) == 0) {
			entry = pool->entries[i];
			DBG("[onion] Onion entry name %s found in pool.",
					entry->hostname);
			goto end;
		}
	}

end:
	return entry;
}

/*
 * Find an onion entry by IP cookie. The pool lock MUST be acquired before
 * calling this.
 *
 * Return entry on success or else NULL.
 */
ATTR_HIDDEN
struct onion_entry *onion_entry_find_by_addr(const struct sockaddr *sa,
		struct onion_pool *pool)
{
	int i;
	struct onion_entry *entry = NULL;
	const struct sockaddr_in *sin;

	assert(sa);

	/* Onion cookie are only IPv4. */
	if (sa->sa_family == AF_INET6) {
		goto end;
	}

	sin = (const struct sockaddr_in *) sa;

	DBG("[onion] Finding onion entry for IP %s",
			inet_ntoa((*((struct in_addr *) &sin->sin_addr.s_addr))));

	/*
	 * XXX: This can be improved by simply getting the offset of the IP with
	 * the pool subnet which gives the index in the pool entries. For instance,
	 * 127.0.0.45 with a ip_subnet set to 127.0.0.0/24, the index in the pool
	 * entries is 45.
	 */
	for (i = 0; i < pool->count; i++) {
		if (pool->entries[i]->ip == sin->sin_addr.s_addr) {
			entry = pool->entries[i];
			DBG("[onion] Onion entry name %s found in pool.",
					entry->hostname);
			goto end;
		}
	}

end:
	return entry;
}
