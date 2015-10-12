/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org> 
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
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

#ifndef CONFIG_FILE_H
#define CONFIG_FILE_H

#include <netinet/in.h>

#include "connection.h"
#include "socks5.h"

/*
 * Represent the values in a configuration file (torsocks.conf). Basically,
 * this is the data structure of a parsed config file.
 */
struct config_file {
	/* The tor address is inet or inet 6. */
	enum connection_domain tor_domain;
	/* The IP of the Tor SOCKS. */
	char *tor_address;
	/* The port of the Tor SOCKS. */
	in_port_t tor_port;

	/*
	 * Base for onion address pool and the mask. In the config file, this is
	 * represented by BASE/MASK like so: 127.0.69.0/24
	 */
	in_addr_t onion_base;
	uint8_t onion_mask;

	/*
	 * Username and password for Tor stream isolation for the SOCKS5 connection
	 * method.
	 */
	char socks5_username[SOCKS5_USERNAME_LEN];
	char socks5_password[SOCKS5_PASSWORD_LEN];
};

/*
 * Structure representing a complete parsed file.
 */
struct configuration {
	/*
	 * Parsed config file (torsocks.conf).
	 */
	struct config_file conf_file;

	/*
	 * Socks5 address so basically where to connect to Tor.
	 */
	struct connection_addr socks5_addr;

	/*
	 * Indicate if we should use SOCKS5 authentication. If this value is set,
	 * both the username and password in the configuration file MUST be
	 * initialized to something of len > 0.
	 */
	unsigned int socks5_use_auth:1;

	/*
	 * Allow inbound connections meaning listen() and accept() are permitted
	 * for non localhost addresses.
	 */
	unsigned int allow_inbound:1;

	/*
	 * Allow outbound connections to localhost that bypass Tor.
	 */
	unsigned int allow_outbound_localhost;

	/*
	 * Automatically set the SOCKS5 authentication to a unique per-process
	 * value. If this value is set, the user MUST NOT have provided a
	 * username or password.
	 */
	unsigned int isolate_pid:1;
};

int config_file_read(const char *filename, struct configuration *config);
void config_file_destroy(struct config_file *conf);
int conf_file_set_tor_address(const char *addr, struct configuration *config);
int conf_file_set_tor_port(const char *port, struct configuration *config);
int conf_file_set_socks5_pass(const char *password,
		struct configuration *config);
int conf_file_set_socks5_user(const char *username,
		struct configuration *config);
int conf_file_set_allow_inbound(const char *val, struct configuration *config);
int conf_file_set_allow_outbound_localhost(const char *val, struct
		configuration *config);
int conf_file_set_isolate_pid(const char *val, struct configuration *config);

int conf_apply_socks_auth(struct configuration *config);

#endif /* CONFIG_FILE_H */
