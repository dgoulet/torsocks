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
#include "helpers.h"

#define NUM_TESTS 5

struct test_host {
	const char *name;
	const char *ip;
};

/* Tor check hostname/ip. */
static const struct test_host tor_check = {
	.name = "perdulce.torproject.org",
	.ip = "138.201.14.203",
};

/* moria1 directory authority. */
static const struct test_host tor_dir_auth1 = {
	.name = "belegost.csail.mit.edu",
	.ip = "128.31.0.39",
};

/* maatuska directory authority. */
static const struct test_host tor_dir_auth2 = {
	.name = "maatuska.4711.se",
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

static void test_gethostbyaddr_r(const struct test_host *host)
{
  int result;
  in_addr_t addr;
  struct hostent ret;
  char buf[1024];
  int buflen = sizeof buf;
  struct hostent *result_entp;
  int h_errno;

  assert(host);
  diag("gethostbyaddr_r test");

  addr = inet_addr(host->ip);
	result = gethostbyaddr_r((const void *)&addr,
				INET_ADDRSTRLEN, AF_INET, &ret, buf, buflen, &result_entp, &h_errno);

  if (result) {
    fail("Resolving address %s: %d", host->ip, result);
  }

  if (strcmp(host->name, result_entp->h_name) != 0) {
    fail("Wrong resolved name: %s", result_entp->h_name);
  }

  if (result_entp->h_addrtype != AF_INET) {
    fail("Wrong resolved address family: %d", result_entp->h_addrtype);
  }

  ok(1, "Resolved address");
}

static void test_gethostbyaddr(const struct test_host *host)
{
	struct hostent *he;
  in_addr_t addr;

	assert(host);

	diag("gethostbyaddr test");

	addr = inet_addr(host->ip);
	he = gethostbyaddr((const void *)&addr, INET_ADDRSTRLEN, AF_INET);
	if (he) {
		ok(strcmp(host->name, he->h_name) == 0, "Resolving address %s", host->ip);
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
	/* Try to connect to SocksPort localhost:9050 and if we can't skip. This is
	 * to avoid to have failing test if no tor daemon is available. */
	if (!helper_is_default_tor_running()) {
		goto end;
	}

	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_getaddrinfo(&tor_check);
	test_gethostbyname(&tor_dir_auth1);
	test_gethostbyaddr(&tor_dir_auth2);
	test_gethostbyaddr_r(&tor_dir_auth2);
	test_getaddrinfo(&tor_localhost);

end:
	return 0;
}
