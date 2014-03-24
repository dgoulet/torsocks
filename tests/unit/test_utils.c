/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *                      Luke Gallagher <luke@hypergeometric.net>
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
#include <stdio.h>

#include <common/utils.h>
#include <common/defaults.h>

#include <tap/tap.h>

#define NUM_TESTS 31

static void test_is_address_ipv4(void)
{
	int ret = 0;

	diag("Utils IPv4 test");

	ret = utils_is_address_ipv4("127.0.0.1");
	ok(ret == 1, "Valid IPv4 address");

	ret = utils_is_address_ipv4("127.0.0.256");
	ok(ret == -1, "Invalid IPv4 address");

	ret = utils_is_address_ipv4("::1");
	ok(ret == -1, "Invalid IPv4 address when IPv6");
}

static void test_is_address_ipv6(void)
{
	int ret = 0;

	diag("Utils IPv6 test");

	ret = utils_is_address_ipv6("::1");
	ok(ret == 1, "Valid IPv6 address");

	ret = utils_is_address_ipv6("2001:DB8:0:0:8:800:200C:417A");
	ok(ret == 1, "Valid IPv6 address");

	ret = utils_is_address_ipv6("2001:DB8:0:0:8:800:200C:G");
	ok(ret == -1, "Invalid IPv6 address");

	ret = utils_is_address_ipv6("192.168.0.1");
	ok(ret == -1, "Invalid IPv6 address when IPv4");
}

static void test_localhost_resolve(void)
{
	int ret = 0;
	in_addr_t ipv4, loopback = htonl(TSOCKS_LOOPBACK);
	struct in6_addr ipv6;
	const uint8_t loopback6[] = TSOCKS_LOOPBACK6;

	diag("Utils localhost resolve test");

	ret = utils_localhost_resolve("localhost", AF_INET, &ipv4, sizeof(ipv4));
	ok(ret == 1, "localhost resolved successfully");
	ok(memcmp(&ipv4, &loopback, sizeof(ipv4)) == 0,
			"localhost IPv4 address matches");

	ret = utils_localhost_resolve("ip-localhost", AF_INET, &ipv4, sizeof(ipv4));
	ok(ret == 1, "ip-localhost resolved successfully");
	ok(memcmp(&ipv4, &loopback, sizeof(ipv4)) == 0,
			"ip-localhost IPv4 address matches");

	ret = utils_localhost_resolve("nsa.gov", AF_INET, &ipv4, sizeof(ipv4));
	ok(ret == 0, "nsa.gov did NOT resolved successfully");

	/* Len smaller than buffer size. */
	ret = utils_localhost_resolve("localhost", AF_INET, &ipv4, 1);
	ok(ret == -EINVAL, "localhost len of buffer was too small");

	/* IPV6 */

	ret = utils_localhost_resolve("localhost", AF_INET6, &ipv6, sizeof(ipv6));
	ok(ret == 1, "localhost v6 resolved successfully");
	ok(memcmp(&ipv6, &loopback6, sizeof(in6addr_loopback)) == 0,
			"localhost IPv6 address matches");

	ret = utils_localhost_resolve("ip6-localhost", AF_INET6, &ipv6,
			sizeof(ipv6));
	ok(ret == 1, "ip6-localhost resolved successfully");
	ok(memcmp(&ipv6, &loopback6, sizeof(in6addr_loopback)) == 0,
			"localhost IPv6 address matches");

	ret = utils_localhost_resolve("nsa.gov", AF_INET6, &ipv6, sizeof(ipv6));
	ok(ret == 0, "nsa.gov did NOT resolved successfully");

	/* Len smaller than buffer size. */
	ret = utils_localhost_resolve("localhost", AF_INET6, &ipv6, 1);
	ok(ret == -EINVAL, "localhost v6 len of buffer was too small");
}

static void test_sockaddr_is_localhost(void)
{
	int ret;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	diag("Utils sockaddr is localhost");

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(TSOCKS_LOOPBACK);
	ret = utils_sockaddr_is_localhost((const struct sockaddr *) &sin);
	ok(ret == 1, "Loopback matches localhost");

	(void) inet_pton(sin.sin_family, "127.8.42.42", &sin.sin_addr.s_addr);
	ret = utils_sockaddr_is_localhost((const struct sockaddr *) &sin);
	ok(ret == 1, "127.8.42.42 matches localhost");

	(void) inet_pton(sin.sin_family, "128.8.42.42", &sin.sin_addr.s_addr);
	ret = utils_sockaddr_is_localhost((const struct sockaddr *) &sin);
	ok(ret == 0, "128.8.42.42 does NO match localhost");

	/* IPv6 */

	sin6.sin6_family = AF_INET6;
	(void) inet_pton(sin6.sin6_family, "::1", &sin6.sin6_addr.s6_addr);
	ret = utils_sockaddr_is_localhost((const struct sockaddr *) &sin6);
	ok(ret == 1, "::1 matches localhost");
}

static void helper_reset_tokens(char **tokens)
{
	assert(tokens);

	int i;
	for (i = 0; i < DEFAULT_MAX_CONF_TOKEN; i++) {
		tokens[i] = NULL;
	}
}

static void test_utils_tokenize_ignore_comments(void)
{
	int nb_token;
	char line[BUFSIZ];
	char *tokens[DEFAULT_MAX_CONF_TOKEN];

	diag("Utils tokenize line test");

	helper_reset_tokens(tokens);
	strcpy(line, "a\tb");
	nb_token = utils_tokenize_ignore_comments(line, sizeof(tokens), tokens);
	ok(nb_token == 2 &&
		(0 == strcmp(tokens[0], "a")) &&
		(0 == strcmp(tokens[1], "b")),
		"Returns 2 tokens");

	helper_reset_tokens(tokens);
	strcpy(line, "foo bar");
	nb_token = utils_tokenize_ignore_comments(line, sizeof(tokens), tokens);
	ok(nb_token == 2 &&
		(0 == strcmp(tokens[0], "foo")) &&
		(0 == strcmp(tokens[1], "bar")),
		"Returns 2 tokens");

	helper_reset_tokens(tokens);
	strcpy(line, "a b c");
	nb_token = utils_tokenize_ignore_comments(line, sizeof(tokens), tokens);
	ok(nb_token == 3 &&
		(0 == strcmp(tokens[0], "a")) &&
		(0 == strcmp(tokens[1], "b")) &&
		(0 == strcmp(tokens[2], "c")),
		"Returns 3 tokens");

	helper_reset_tokens(tokens);
	strcpy(line, "# this is a comment");
	nb_token = utils_tokenize_ignore_comments(line, sizeof(tokens), tokens);
	ok(nb_token == 0, "Returns 0 tokens for comment");
}

static void test_is_addr_any(void)
{
	int ret;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(42);
	inet_pton(sin.sin_family, "0.0.0.0", &sin.sin_addr);

	ret = utils_is_addr_any((const struct sockaddr *) &sin);
	ok(ret == 1, "This address is 0.0.0.0");

	sin.sin_family = AF_INET;
	sin.sin_port = htons(42);
	inet_pton(sin.sin_family, "1.0.0.0", &sin.sin_addr);

	ret = utils_is_addr_any((const struct sockaddr *) &sin);
	ok(ret == 0, "This address is NOT 0.0.0.0");

	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(42);
	inet_pton(sin6.sin6_family, "::", &sin6.sin6_addr);

	ret = utils_is_addr_any((const struct sockaddr *) &sin6);
	ok(ret == 1, "This address is ::");

	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(42);
	inet_pton(sin6.sin6_family, "fe80::1", &sin6.sin6_addr);

	ret = utils_is_addr_any((const struct sockaddr *) &sin6);
	ok(ret == 0, "This address is NOT ::");
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_is_address_ipv4();
	test_is_address_ipv6();
	test_localhost_resolve();
	test_sockaddr_is_localhost();
	test_utils_tokenize_ignore_comments();
	test_is_addr_any();

	return exit_status();
}
