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

#include <assert.h>
#include <dlfcn.h>
#include <stdlib.h>

#include <common/config-file.h>
#include <common/connection.h>
#include <common/defaults.h>
#include <common/log.h>
#include <common/socks5.h>

#include "torsocks.h"

/*
 * Global configuration of torsocks taken from the configuration file or set
 * with the defaults. This is initialized in the constructor once and only
 * once. Once done, this object is *immutable* thus no locking is needed to
 * read this object as long as there is not write action.
 */
struct configuration tsocks_config;

/*
 * Set to 1 if the binary is set with suid or 0 if not. This is set once during
 * initialization so after that it can be read without any protection.
 */
static int is_suid;

/*
 * Cleanup and exit with the given status. Note that the lib destructor will be
 * called after this call.
 */
static void clean_exit(int status)
{
	exit(status);
}

/*
 * Initialize torsocks configuration from a given conf file or the default one.
 */
static void init_config(void)
{
	int ret;
	const char *filename = NULL;

	if (!is_suid) {
		filename = getenv("TORSOCKS_CONF_FILE");
	}

	ret  = config_file_read(filename, &tsocks_config);
	if (ret < 0) {
		/*
		 * Failing to get the configuration means torsocks can not function
		 * properly so stops everything.
		 */
		clean_exit(EXIT_FAILURE);
	}

	/*
	 * Setup configuration from config file. Use defaults if some attributes
	 * are missing.
	 */
	if (!tsocks_config.conf_file.tor_address) {
		tsocks_config.conf_file.tor_address = strdup(DEFAULT_TOR_ADDRESS);
	}
	if (tsocks_config.conf_file.tor_port == 0) {
		tsocks_config.conf_file.tor_port = DEFAULT_TOR_PORT;
	}
	if (tsocks_config.conf_file.tor_domain == 0) {
		tsocks_config.conf_file.tor_domain = DEFAULT_TOR_DOMAIN;
	}

	/* Create the Tor SOCKS5 connection address. */
	ret = connection_addr_set(tsocks_config.conf_file.tor_domain,
			tsocks_config.conf_file.tor_address,
			tsocks_config.conf_file.tor_port, &tsocks_config.socks5_addr);
	if (ret < 0) {
		/*
		 * Without a valid connection address object to Tor well torsocks can't
		 * work properly at all so abort everything.
		 */
		clean_exit(EXIT_FAILURE);
	}
}

/*
 * Save all the original libc function calls that torsocks needs.
 */
static void init_libc_symbols(void)
{
	tsocks_libc_connect = tsocks_find_libc_symbol(LIBC_CONNECT_NAME_STR,
			TSOCKS_SYM_EXIT_NOT_FOUND);
}

/*
 * Initialize logging subsytem using either the default values or the one given
 * by the environment variables.
 */
static void init_logging(void)
{
	int level;
	const char *filepath = NULL, *level_str, *time_status_str;
	enum log_time_status t_status;

	/* Get log level from user or use default. */
	level_str = getenv(DEFAULT_LOG_LEVEL_ENV);
	if (level_str) {
		level = atoi(level_str);
	} else {
		/* Set to the default loglevel. */
		level = tsocks_loglevel;
	}

	/* Get time status from user or use default. */
	time_status_str = getenv(DEFAULT_LOG_TIME_ENV);
	if (time_status_str) {
		t_status = atoi(time_status_str);
	} else {
		t_status = DEFAULT_LOG_TIME_STATUS;
	}

	/* NULL value is valid which will set the output to stderr. */
	if (!is_suid) {
		filepath = getenv(DEFAULT_LOG_FILEPATH_ENV);
	}

	/*
	 * The return value is not important because this call will output the
	 * errors to the user if needed. Worst case, there is no logging.
	 */
	(void) log_init(level, filepath, t_status);

	/* After this, it is safe to call any logging macros. */

	DBG("Logging subsytem initialized. Level %d, file %s, time %d",
			level, filepath, t_status);
}

/*
 * Lib constructor. Initialize torsocks here before the main execution of the
 * binary we are preloading.
 */
static void __attribute__((constructor)) tsocks_init(void)
{
	/* UID and effective UID MUST be the same or else we are SUID. */
	is_suid = (getuid() != geteuid());

	init_logging();

	/*
	 * We need to save libc symbols *before* we override them so torsocks can
	 * use the original libc calls.
	 */
	init_libc_symbols();

	/*
	 * Read configuration file and set the global config.
	 */
	init_config();

	/* Initialize connection reigstry. */
	connection_registry_init();
}

/*
 * Lib destructor.
 */
static void __attribute__((destructor)) tsocks_exit(void)
{
	/* Cleanup allocated memory in the config file. */
	config_file_destroy(&tsocks_config.conf_file);
	/* Clean up logging. */
	log_destroy();
}

/*
 * Setup a Tor connection meaning initiating the initial SOCKS5 handshake.
 *
 * Return 0 on success else a negative value.
 */
static int setup_tor_connection(struct connection *conn)
{
	int ret;

	assert(conn);

	DBG("Setting up a connection to the Tor network on fd %d", conn->fd);

	ret = socks5_connect(conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_send_method(conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_recv_method(conn);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Initiate a SOCK5 connection to the Tor network using the given connection.
 * The socks5 API will use the torsocks configuration object to find the tor
 * daemon.
 *
 * Return 0 on success or else a negative value being the errno value that
 * needs to be sent back.
 */
int tsocks_connect_to_tor(struct connection *conn)
{
	int ret;

	assert(conn);

	DBG("Connecting to the Tor network on fd %d", conn->fd);

	ret = setup_tor_connection(conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_send_connect_request(conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_recv_connect_reply(conn);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Resolve a hostname through Tor and set the ip address in the given pointer.
 *
 * Return 0 on success else a negative value and the result addr is untouched.
 */
int tsocks_tor_resolve(const char *hostname, uint32_t *ip_addr)
{
	int ret;
	struct connection conn;

	assert(hostname);
	assert(ip_addr);

	DBG("Resolving %s on the Tor network", hostname);

	conn.fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (conn.fd < 0) {
		PERROR("socket");
		ret = -errno;
		goto error;
	}

	ret = setup_tor_connection(&conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_send_resolve_request(hostname, &conn);
	if (ret < 0) {
		goto error;
	}

	/* Force IPv4 resolution for now. */
	ret = socks5_recv_resolve_reply(&conn, ip_addr, sizeof(uint32_t));
	if (ret < 0) {
		goto error;
	}

	ret = close(conn.fd);
	if (ret < 0) {
		PERROR("close");
	}

error:
	return ret;
}

/*
 * Lookup symbol in the loaded libraries of the binary.
 *
 * Return the function pointer or NULL on error.
 */
void *tsocks_find_libc_symbol(const char *symbol,
		enum tsocks_sym_action action)
{
	void *fct_ptr = NULL;

	assert(symbol);

	fct_ptr = dlsym(RTLD_NEXT, symbol);
	if (!fct_ptr) {
		ERR("Unable to find %s", symbol);
		if (action == TSOCKS_SYM_EXIT_NOT_FOUND) {
			ERR("This is critical for torsocks. Exiting");
			clean_exit(EXIT_FAILURE);
		}
	}

	return fct_ptr;
}
