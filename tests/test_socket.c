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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include <lib/torsocks.h>

#include <tap/tap.h>

#define NUM_TESTS 18

static void test_socketpair_types(void)
{
	int fd[2], ret1, ret2, err;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	ret1 = close(fd[0]);
	ret2 = close(fd[1]);
	ok (fd[0] != -1 && fd[1] != -1 && !err && ret1 == 0 && ret2 == 0,
			"Unix socket valid for socketpair");

	err = socketpair(AF_INET, SOCK_STREAM, 0, fd);
	ok (err == -1 && errno == EPERM, "INET socket NOT valid for socketpair");

	err = socketpair(AF_INET6, SOCK_STREAM, 0, fd);
	ok (err == -1 && errno == EPERM, "INET6 socket NOT valid for socketpair");
}

static void test_socket_types(void)
{
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "Unix socket is valid");

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "AF local socket is valid");

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv4 TCP socket is valid");

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv4 TCP non block socket is valid");

	fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv4 TCP non block/cloexec socket is valid");

	fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv6 TCP socket is valid");

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv6 TCP non block socket is valid");

	fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			IPPROTO_IP);
	ret = close(fd);
	ok (fd != -1 && ret == 0, "IPv6 TCP non block/cloexec socket is valid");

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ok (fd == -1 && errno == EPERM,
			"IPv4 UDP socket is NOT valid");

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	ok (fd == -1 && errno == EPERM,
			"IPv4 UDP non block socket is NOT valid");

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			IPPROTO_UDP);
	ok (fd == -1 && errno == EPERM,
			"IPv4 UDP non block/cloexec socket is NOT valid");

	fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	ok (fd == -1 && errno == EPERM,
			"IPv6 UDP socket is NOT valid");

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	ok (fd == -1 && errno == EPERM,
			"IPv4 RAW socket is NOT valid");

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	ok (fd == -1 && errno == EPERM,
			"IPv4 RAW ICMP socket is NOT valid");

	fd = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	ok (fd == -1 && errno == EPERM,
			"IPv6 RAW socket is NOT valid");
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_socket_types();
	test_socketpair_types();

    return 0;
}
