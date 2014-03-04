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

#ifndef TORSOCKS_DEFAULTS_H
#define TORSOCKS_DEFAULTS_H

#include "connection.h"
#include "log.h"

#define DEFAULT_TOR_PORT	9050
#define DEFAULT_TOR_ADDRESS	"127.0.0.1"
#define DEFAULT_TOR_DOMAIN  CONNECTION_DOMAIN_INET

/* Logging defaults. */
#define DEFAULT_LOG_LEVEL_ENV		"TORSOCKS_LOG_LEVEL"
#define DEFAULT_LOG_TIME_ENV		"TORSOCKS_LOG_TIME"
#define DEFAULT_LOG_FILEPATH_ENV	"TORSOCKS_LOG_FILE_PATH"
#define DEFAULT_LOG_TIME_STATUS		LOG_TIME_ADD
#define DEFAULT_LOG_LEVEL			MSGWARN

/*
 * RFC 1035 specifies a maxium of 255 possibe for domain name.
 * (https://www.ietf.org/rfc/rfc1035.txt).
 */
#define DEFAULT_DOMAIN_NAME_SIZE	255

#define DEFAULT_CONF_FILENAME		"torsocks.conf"
#define DEFAULT_CONF_FILE			CONFDIR "/tor/" DEFAULT_CONF_FILENAME
#define DEFAULT_CONF_FILE_ENV		"TORSOCKS_CONF_FILE"

/*
 * Maximum number of token in a single line of the torsocks configuration file.
 * For instance, "TorAddress 127.0.0.1" is two tokens.
 */
#define DEFAULT_MAX_CONF_TOKEN		5

/*
 * Default initial size of the onion pool.
 */
#define DEFAULT_ONION_POOL_SIZE		8

/*
 * The default onion pool cookie range starting at 0 up to 255.
 */
#define DEFAULT_ONION_ADDR_RANGE	"127.42.42.0"
#define DEFAULT_ONION_ADDR_MASK		"24"

/* Env. variable for SOCKS5 authentication */
#define DEFAULT_SOCKS5_USER_ENV     "TORSOCKS_USERNAME"
#define DEFAULT_SOCKS5_PASS_ENV     "TORSOCKS_PASSWORD"

/* Control if torsocks allows inbound connection or not. */
#define DEFAULT_ALLOW_INBOUND_ENV   "TORSOCKS_ALLOW_INBOUND"

#endif /* TORSOCKS_DEFAULTS_H */
