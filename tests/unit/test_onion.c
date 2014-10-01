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
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include <common/onion.h>
#include <common/defaults.h>

#include <tap/tap.h>

#define NUM_TESTS 12

static void test_onion_entry(struct onion_pool *pool)
{
	int ret;
	struct onion_entry *entry;
	const char *onion_addr1 = "87idq6tnejk5plpn.onion";
	const char *onion_addr2 = "97idq6tnejk5plpn.onion";
	const char *onion_addr1_typo = "87idq6tnejk5plpn.onio";
	struct sockaddr_in sin;

	diag("Onion entry subsystem initialization test");

	/* Create valid onion pool from default values. */
	ret = onion_pool_init(pool, inet_addr(DEFAULT_ONION_ADDR_RANGE),
			(uint8_t) atoi(DEFAULT_ONION_ADDR_MASK));
	ok(ret == 0 &&
		pool->base == 0 &&
		pool->max_pos == 255 &&
		pool->size == 8 &&
		pool->count == 0 &&
		pool->next_entry_pos == 0,
		"Valid onion pool created");

	entry = onion_entry_create(pool, onion_addr1);
	ok(entry &&
		pool->count == 1 &&
		pool->next_entry_pos == 1 &&
		strcmp(entry->hostname, onion_addr1) == 0 &&
		strcmp(DEFAULT_ONION_ADDR_RANGE,
			inet_ntoa(*((struct in_addr *) &entry->ip))) == 0,
		"Valid onion entry %s created", onion_addr1);

	entry = onion_entry_find_by_name("meh", pool);
	ok(!entry, "Onion entry not found");

	entry = onion_entry_find_by_name(onion_addr1_typo, pool);
	ok(!entry, "Onion entry with typo not found");

	entry = onion_entry_find_by_name(onion_addr1, pool);
	ok(entry &&
		pool->count == 1 &&
		strcmp(entry->hostname, onion_addr1) == 0 &&
		strcmp(DEFAULT_ONION_ADDR_RANGE,
			inet_ntoa(*((struct in_addr *) &entry->ip))) == 0,
		"Valid onion entry found by name");

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(DEFAULT_ONION_ADDR_RANGE);
	entry = onion_entry_find_by_addr((const struct sockaddr *) &sin, pool);
	ok(entry &&
		pool->count == 1 &&
		strcmp(entry->hostname, onion_addr1) == 0 &&
		strcmp(DEFAULT_ONION_ADDR_RANGE,
			inet_ntoa(*((struct in_addr *) &entry->ip))) == 0,
		"Valid onion entry found by IP");

	entry = onion_entry_create(pool, onion_addr2);
	ok(entry &&
		pool->count == 2 &&
		pool->next_entry_pos == 2 &&
		strcmp(entry->hostname, onion_addr2) == 0 &&
		strcmp("127.42.42.1",
			inet_ntoa(*((struct in_addr *) &entry->ip))) == 0,
		"Valid onion entry %s created", onion_addr2);

	onion_pool_destroy(pool);
}

static void test_onion_init(struct onion_pool *pool)
{
	int ret;
	uint8_t mask;
	in_addr_t base;

	diag("Onion subsystem initialization test");

	/* Valid default configuration test. */
	base = inet_addr(DEFAULT_ONION_ADDR_RANGE);
	mask = (uint8_t) atoi(DEFAULT_ONION_ADDR_MASK);
	ret = onion_pool_init(pool, base, mask);
	ok(ret == 0 &&
		pool->entries &&
		pool->base == 0 &&
		pool->max_pos == 255 &&
		pool->size == 8 &&
		pool->count == 0 &&
		pool->next_entry_pos == 0,
		"Valid onion pool of %s/%d", DEFAULT_ONION_ADDR_RANGE, mask);
	onion_pool_destroy(pool);

	/* Valid test. */
	base = inet_addr("127.42.42.64");
	mask = 27;
	ret = onion_pool_init(pool, base, mask);
	ok(ret == 0 &&
		pool->entries &&
		pool->base == 64 &&
		pool->max_pos == 95 &&
		pool->size == 8 &&
		pool->count == 0 &&
		pool->next_entry_pos == 0,
		"Valid onion pool of 127.42.42.64/27");
	onion_pool_destroy(pool);

	/* Valid test. */
	base = inet_addr("127.42.42.64");
	mask = 17;
	ret = onion_pool_init(pool, base, mask);
	ok(ret == 0 &&
		pool->entries &&
		pool->base == 0 &&
		pool->max_pos == 32767 &&
		pool->size == 8 &&
		pool->count == 0 &&
		pool->next_entry_pos == 0,
		"Valid onion pool of 127.42.42.64/17");
	onion_pool_destroy(pool);

	/* Valid test with size less than default. */
	base = inet_addr("127.42.42.0");
	mask = 32;
	ret = onion_pool_init(pool, base, mask);
	ok(ret == 0 &&
		pool->entries &&
		pool->base == 0 &&
		pool->max_pos == 0 &&
		pool->size == 1 &&
		pool->count == 0 &&
		pool->next_entry_pos == 0,
		"Valid onion pool of 127.42.42.0/32");
	onion_pool_destroy(pool);

	/* Invalid test. */
	base = inet_addr("127.42.42.64");
	mask = 42;
	ret = onion_pool_init(pool, base, mask);
	ok(ret == -EINVAL,
		"Invalid onion pool of mask 42");
}

int main(int argc, char **argv)
{
	struct onion_pool pool;

	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_onion_init(&pool);
	test_onion_entry(&pool);

    return 0;
}
