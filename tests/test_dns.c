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
#include <stdlib.h>
#include <sys/socket.h>

#include <lib/torsocks.h>

#include <tap/tap.h>

#define NUM_TESTS 4

struct test_host {
	const char *name;
	const char *ip;
};

/* Tor check hostname/ip. */
static const struct test_host tor_check = {
	.name = "sergii.torproject.org",
	.ip = "38.229.72.22",
};

/* moria1 directory authority. */
static const struct test_host tor_dir_auth1 = {
	.name = "belegost.csail.mit.edu",
	.ip = "128.31.0.39",
};

/* maatuska directory authority. */
static const struct test_host tor_dir_auth2 = {
	.name = "ehlo.4711.se",
	.ip = "171.25.193.9",
};

/* localhost resolution. */
static const struct test_host tor_localhost = {
	.name = "localhost",
	.ip = "127.0.0.1",
};

static void test_gethostbyname(const struct test_host *host)
{
    struct hostent *he;

	assert(host);

	diag("gethostbyname test");

    he = gethostbyname(host->name);
    if (he) {
		char *addr = inet_ntoa(*((struct in_addr *) he->h_addr_list[0]));
		ok(strcmp(addr, host->ip) == 0, "Resolving %s", host->name);
    } else {
		fail("Resolving %s", host->name);
	}

	return;
}

static void test_gethostbyaddr(const struct test_host *host)
{
	struct hostent *he;
    in_addr_t addr;

	assert(host);

	diag("gethostbyaddr test");

    addr = inet_addr(host->ip);

    he = gethostbyaddr(&addr, INET_ADDRSTRLEN, AF_INET);
    if (he) {
		ok(strcmp(host->name, he->h_name) == 0,
				"Resolving address %s", host->ip);
    } else {
		fail("Resolving address %s", host->ip);
	}

    return;
}

static void test_getaddrinfo(const struct test_host *host)
{
	int ret;
    struct addrinfo hints;
    struct addrinfo *result = NULL;

	diag("getaddrinfo test");

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    ret = getaddrinfo(host->name, NULL, &hints, &result);
    if (ret == 0) {
		struct in_addr addr;
		char *ip;

		addr.s_addr = ((struct sockaddr_in *)(result->ai_addr))->sin_addr.s_addr;
		ip = inet_ntoa(addr);

		ok(strcmp(host->ip, ip) == 0,
				"Resolving address %s with getaddrinfo", host->name);
    } else {
		printf("%s\n", gai_strerror(ret));
		fail("Resolving address %s with getaddrinfo", host->name);
	}

	free(result);
    return;
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_getaddrinfo(&tor_check);
    test_gethostbyname(&tor_dir_auth1);
	test_gethostbyaddr(&tor_dir_auth2);
	test_getaddrinfo(&tor_localhost);

    return 0;
}
