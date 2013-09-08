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
#include <arpa/inet.h>
#include <stdlib.h>
#include <limits.h>

#include <common/utils.h>
#include <common/defaults.h>
#include <common/config-file.h>

#include <tap/tap.h>
#include <fixtures.h>

#define NUM_TESTS 11

static void test_config_file_read_none(void)
{
	int ret = 0;
	struct configuration config;
	char buf[DEFAULT_DOMAIN_NAME_SIZE];

	diag("Config file read none");

	ret = config_file_read(NULL, &config);
	inet_ntop(AF_INET, &config.conf_file.onion_base, buf, sizeof(buf));
	ok(ret == 0 &&
		config.conf_file.tor_port == DEFAULT_TOR_PORT &&
		strcmp(config.conf_file.tor_address, DEFAULT_TOR_ADDRESS) == 0 &&
		strcmp(buf, DEFAULT_ONION_ADDR_RANGE) == 0 &&
		config.conf_file.onion_mask == strtoul(DEFAULT_ONION_ADDR_MASK, NULL, 0),
		"Use default when no config file");
}

static void test_config_file_read_valid(void)
{
	int ret = 0;
	struct configuration config;
	char buf[DEFAULT_DOMAIN_NAME_SIZE];

	diag("Config file read valid");

	ret = config_file_read(fixture("config0"), &config);
	inet_ntop(AF_INET, &config.conf_file.onion_base, buf, sizeof(buf));
	ok(ret == 0 &&
		config.conf_file.tor_port == DEFAULT_TOR_PORT &&
		strcmp(config.conf_file.tor_address, DEFAULT_TOR_ADDRESS) == 0 &&
		strcmp(buf, DEFAULT_ONION_ADDR_RANGE) == 0 &&
		config.conf_file.onion_mask == strtoul(DEFAULT_ONION_ADDR_MASK, NULL, 0),
		"Read valid config file");
}

static void test_config_file_read_empty(void)
{
	int ret = 0;
	struct configuration config;
	char buf[DEFAULT_DOMAIN_NAME_SIZE];

	diag("Config file read empty");

	ret = config_file_read(fixture("config1"), &config);
	inet_ntop(AF_INET, &config.conf_file.onion_base, buf, sizeof(buf));
	ok(ret == 0 &&
		config.conf_file.tor_port == 0 &&
		config.conf_file.tor_address == NULL &&
		strcmp(buf, "0.0.0.0") == 0 &&
		config.conf_file.onion_mask == 0,
		"Read empty config file");
}

static void test_config_file_read_invalid_values(void)
{
	int ret = 0;
	struct configuration config;

	diag("Config file read invalid values");

	ret = config_file_read(fixture("config2"), &config);
	ok(ret == -EINVAL &&
		config.conf_file.tor_port == 0,
		"TorPort 65536 returns -EINVAL");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config3"), &config);
	ok(ret == -EINVAL &&
		config.conf_file.tor_port == 0,
		"TorPort 0 returns -EINVAL");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config4"), &config);
	ok(ret == -1 &&
		config.conf_file.tor_address == NULL,
		"TorAddress invalid IPv4 returns -1");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config5"), &config);
	ok(ret == -1 &&
		config.conf_file.tor_address == NULL,
		"TorAddress invalid IPv6 returns -1");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config6"), &config);
	ok(ret == -EINVAL &&
		config.conf_file.onion_mask == 0,
		"OnionAdrRange invalid range returns -EINVAL");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config7"), &config);
	ok(ret == -EINVAL &&
		config.conf_file.onion_base == 0,
		"OnionAdrRange invalid IPv4 address returns -EINVAL");

	memset(&config, 0x0, sizeof(config));
	ret = config_file_read(fixture("config8"), &config);
	ok(ret == -EINVAL &&
		config.conf_file.onion_base == 0,
		"OnionAdrRange invalid IPv6 address returns -EINVAL");

	memset(&config, 0x0, sizeof(config));
#if (defined(__LP64__))
	ret = config_file_read(fixture("config9_64"), &config);
#else
	ret = config_file_read(fixture("config9_32"), &config);
#endif
	ok(ret == -EINVAL &&
		config.conf_file.onion_base == 0,
		"OnionAdrRange invalid mask returns -EINVAL");
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_config_file_read_none();
	skip_start(0 == TORSOCKS_FIXTURE_PATH, 10, "TORSOCKS_FIXTURE_PATH not defined");
	test_config_file_read_valid();
	test_config_file_read_empty();
	test_config_file_read_invalid_values();
	skip_end();

	return exit_status();
}
