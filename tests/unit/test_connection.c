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

#include <common/connection.h>
#include <common/defaults.h>

#include <tap/tap.h>

#define NUM_TESTS 13

static void test_connection_usage(void)
{
	int ret;
	struct connection *conn, *conn2, *l_conn;
	struct connection_addr c_addr;

	diag("Connection subsystem creation test");

	ret = connection_addr_set(CONNECTION_DOMAIN_INET, "127.0.0.1", 9050,
			&c_addr);
	ok(ret == 0 &&
		c_addr.domain == CONNECTION_DOMAIN_INET &&
		c_addr.u.sin.sin_family == AF_INET &&
		c_addr.u.sin.sin_port == htons(9050),
		"Valid connection address creation");

	conn = connection_create(42, (struct sockaddr *) &c_addr.u.sin);
	ok(conn &&
		conn->fd == 42 &&
		conn->dest_addr.domain == CONNECTION_DOMAIN_INET &&
		conn->refcount.count == 1,
		"Valid connection creation");

	conn2 = connection_create(43, (struct sockaddr *) &c_addr.u.sin);
	ok(conn2 &&
		conn2->fd == 43 &&
		conn2->dest_addr.domain == CONNECTION_DOMAIN_INET &&
		conn2->refcount.count == 1,
		"Valid second connection creation");

	connection_registry_lock();
	connection_insert(conn);
	l_conn = connection_find(conn->fd);
	ok(conn == l_conn, "Valid connection insert/find");

	connection_insert(conn2);
	l_conn = connection_find(conn2->fd);
	ok(conn2 == l_conn, "Valid second connection insert/find");

	connection_remove(conn);
	l_conn = connection_find(conn->fd);
	ok(conn != l_conn, "Valid connection remove/find");

	connection_remove(conn2);
	l_conn = connection_find(conn2->fd);
	ok(conn2 != l_conn, "Valid second connection remove/find");
	connection_registry_unlock();

	connection_destroy(conn);
	connection_destroy(conn2);
}

static void test_connection_creation(void)
{
	int ret;
	struct connection *conn;
	struct connection_addr c_addr;

	diag("Connection subsystem creation test");

	ret = connection_addr_set(CONNECTION_DOMAIN_INET, "127.0.0.1", 9050,
			&c_addr);
	ok(ret == 0 &&
		c_addr.domain == CONNECTION_DOMAIN_INET &&
		c_addr.u.sin.sin_family == AF_INET &&
		c_addr.u.sin.sin_port == htons(9050),
		"Valid connection address creation");

	conn = connection_create(42, (struct sockaddr *) &c_addr.u.sin);
	ok(conn &&
		conn->fd == 42 &&
		conn->dest_addr.domain == CONNECTION_DOMAIN_INET &&
		conn->refcount.count == 1,
		"Valid connection creation");
	connection_destroy(conn);

	conn = connection_create(-1, (struct sockaddr *) &c_addr.u.sin);
	ok(conn &&
		conn->fd == -1 &&
		conn->dest_addr.domain == CONNECTION_DOMAIN_INET &&
		conn->refcount.count == 1,
		"Valid connection creation with fd -1");
	connection_destroy(conn);

	conn = connection_create(42, NULL);
	ok(conn &&
		conn->fd == 42 &&
		conn->dest_addr.domain == 0 &&
		conn->refcount.count == 1,
		"Valid connection creation with sockaddr NULL");
	connection_destroy(conn);

	ret = connection_addr_set(CONNECTION_DOMAIN_INET6, "::1", 9050,
			&c_addr);
	ok(ret == 0 &&
		c_addr.domain == CONNECTION_DOMAIN_INET6 &&
		c_addr.u.sin.sin_family == AF_INET6 &&
		c_addr.u.sin.sin_port == htons(9050),
		"Valid connection address creation for IPv6");

	conn = connection_create(42, (struct sockaddr *) &c_addr.u.sin6);
	ok(conn &&
		conn->fd == 42 &&
		conn->dest_addr.domain == CONNECTION_DOMAIN_INET6 &&
		conn->refcount.count == 1,
		"Valid connection creation for IPv6");
	connection_destroy(conn);
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_connection_creation();
	test_connection_usage();

    return 0;
}
