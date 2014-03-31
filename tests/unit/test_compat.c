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

#include <common/compat.h>

#include <tap/tap.h>

#define NUM_TESTS 7

static void test_socket_stream(void)
{
	int type, ret;

	type = SOCK_STREAM;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 1, "Type SOCK_STREAM valid");

	type = SOCK_STREAM | SOCK_NONBLOCK;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 1, "Type SOCK_STREAM | SOCK_NONBLOCK valid");

	type = SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 1, "Type SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC valid");

	type = SOCK_STREAM | 42;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 0, "Type SOCK_STREAM | 42 is NOT a stream socket");

	type = SOCK_DGRAM;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 0, "Type SOCK_DGRAM is NOT a stream socket");

	type = SOCK_DGRAM | SOCK_NONBLOCK;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 0, "Type SOCK_DGRAM  | SOCK_NONBLOCK is NOT a stream socket");

	type = SOCK_RAW;
	ret = IS_SOCK_STREAM(type);
	ok (ret == 0, "Type SOCK_RAW is NOT a stream socket");
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_socket_stream();

    return 0;
}
