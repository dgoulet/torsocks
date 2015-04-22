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

#define NUM_TESTS 7

static void test_getpeername(void)
{
	int pipe_fds[2], ret, inet_sock = -1;
	char buf[INET_ADDRSTRLEN];
	struct sockaddr addr;
	struct sockaddr_in addrv4;
	struct sockaddr_storage ss;
	socklen_t addrlen;
	const char *ip = "93.95.227.222";

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("Unable to create pipe");
		goto error;
	}

	/* This test is to see if we go through the libc or not. */
	ret = getpeername(pipe_fds[0], NULL, NULL);
	ok(ret == -1 && errno == ENOTSOCK, "Invalid socket fd");

	close(pipe_fds[0]);
	close(pipe_fds[1]);

	/* Create inet socket. */
	inet_sock = socket(AF_INET, SOCK_STREAM, 0);
	ok(inet_sock >= 0, "Inet socket created");

	/* This test is to see if we go through the libc or not. */
	ret = getpeername(inet_sock, &addr, &addrlen);
	ok(ret == -1 && errno == ENOTCONN, "Socket not connected");

	/* Connect socket through Tor so we can test the wrapper. */
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(443);
	inet_pton(addrv4.sin_family, ip, &addrv4.sin_addr);
	memset(addrv4.sin_zero, 0, sizeof(addrv4.sin_zero));

	ret = connect(inet_sock, (struct sockaddr *) &addrv4, sizeof(addrv4));
	if (ret < 0) {
		fail("Unable to connect to %s", ip);
		goto error;
	}

	/* Invalid arguments */
	addrlen = sizeof(addr);
	ret = getpeername(inet_sock, NULL, &addrlen);
	ok(ret == -1 && errno == EFAULT, "Invalid addr ptr");

	ret = getpeername(inet_sock, &addr, NULL);
	ok(ret == -1 && errno == EFAULT, "Invalid addrlen ptr");

	addrlen = sizeof(addrv4);
	memset(&addrv4, 0, addrlen);
	ret = getpeername(inet_sock, (struct sockaddr *) &addrv4, &addrlen);

	/* Validate returned IP address. */
	memset(buf, 0, sizeof(buf));
	inet_ntop(addrv4.sin_family, &addrv4.sin_addr, buf, sizeof(buf));
	ok(ret == 0 && strncmp(buf, ip, strlen(ip)) == 0,
			"Valid returned IP address from getpeername()");

	/* Large but valid addrlen. */
	addrlen = sizeof(ss);
	ret = getpeername(inet_sock, (struct sockaddr *)&ss, &addrlen);
	ok(ret == 0 && addrlen == sizeof(addrv4), "Valid returned IP address from getpeername(), large addrlen");

error:
	if (inet_sock >= 0) {
		close(inet_sock);
	}
	return;
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_getpeername();

    return 0;
}
