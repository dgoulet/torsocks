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

#include <stdio.h>

#include <common/utils.h>
#include <common/defaults.h>

#include <tap/tap.h>

#define NUM_TESTS 10

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

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_is_address_ipv4();
	test_is_address_ipv6();
	test_utils_tokenize_ignore_comments();

	return exit_status();
}
