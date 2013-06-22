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

#include <arpa/inet.h>
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
 * Lookup symbol in the loaded libraries of the binary.
 *
 * Return the function pointer or NULL on error.
 */
static void *find_libc_symbol(const char *symbol,
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
	tsocks_libc_connect = find_libc_symbol(LIBC_CONNECT_NAME_STR,
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
static int connect_to_tor_network(struct connection *conn)
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
static int tor_resolve(const char *hostname, uint32_t *ip_addr)
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

	ret = socks5_recv_resolve_reply(&conn, ip_addr);
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
 * Torsocks call for connect(2).
 */
LIBC_CONNECT_RET_TYPE tsocks_connect(LIBC_CONNECT_SIG)
{
	int ret, sock_type;
	socklen_t optlen;
	struct connection *new_conn;

	DBG("Connect catched on fd %d", __sockfd);

	ret = getsockopt(__sockfd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen);
	if (ret < 0) {
		/* Use the getsockopt() errno value. */
		goto error;
	}

	/* We can't handle a non inet socket. */
	if (__addr->sa_family != AF_INET &&
			__addr->sa_family != AF_INET6) {
		DBG("[conect] Connection is not IPv4/v6. Ignoring.");
		goto libc_connect;
	}

	/*
	 * Refuse non stream socket. There is a chance that this might be a DNS
	 * request that we can't pass through Tor using raw UDP packet.
	 */
	if (sock_type != SOCK_STREAM) {
		ERR("[connect] UDP or ICMP stream can't be handled. Rejecting.");
		errno = EBADF;
		goto error;
	}

	/*
	 * Lock registry to get the connection reference if one. In this code path,
	 * if a connection object is found, it will not be used since a double
	 * connect() on the same file descriptor is an error so the registry is
	 * quickly unlocked and no reference is needed.
	 */
	connection_registry_lock();
	new_conn = connection_find(__sockfd);
	connection_registry_unlock();
	if (new_conn) {
		/* Double connect() for the same fd. */
		errno = EISCONN;
		goto error;
	}

	new_conn = connection_create(__sockfd, __addr);
	if (!new_conn) {
		errno = ENOMEM;
		goto error;
	}

	/* Connect the socket to the Tor network. */
	ret = connect_to_tor_network(new_conn);
	if (ret < 0) {
		errno = -ret;
		goto error;
	}

	connection_registry_lock();
	/* This can't fail since a lookup was done previously. */
	connection_insert(new_conn);
	connection_registry_unlock();

	/* Flag errno for success */
	ret = errno = 0;
	return ret;

libc_connect:
	return tsocks_libc_connect(LIBC_CONNECT_ARGS);
error:
	/* At this point, errno MUST be set to a valid connect() error value. */
	return -1;
}

/*
 * Libc hijacked symbol connect(2).
 */
LIBC_CONNECT_DECL
{
	/* Find symbol if not already set. Exit if not found. */
	tsocks_libc_connect = find_libc_symbol(LIBC_CONNECT_NAME_STR,
			TSOCKS_SYM_EXIT_NOT_FOUND);
	return tsocks_connect(LIBC_CONNECT_ARGS);
}

/*
 * Torsocks call for gethostbyname(3).
 *
 * NOTE: This call is OBSOLETE in the glibc.
 */
LIBC_GETHOSTBYNAME_RET_TYPE tsocks_gethostbyname(LIBC_GETHOSTBYNAME_SIG)
{
	int ret;
	uint32_t ip;
	const char *ret_str;

	DBG("[gethostbyname] Requesting %s hostname", __name);

	if (!__name) {
		h_errno = HOST_NOT_FOUND;
		goto error;
	}

	/* Resolve the given hostname through Tor. */
	ret = tor_resolve(__name, &ip);
	if (ret < 0) {
		goto error;
	}

	/* Reset static host entry of tsocks. */
	memset(&tsocks_he, 0, sizeof(tsocks_he));
	memset(tsocks_he_addr_list, 0, sizeof(tsocks_he_addr_list));
	memset(tsocks_he_addr, 0, sizeof(tsocks_he_addr));

	ret_str = inet_ntop(AF_INET, &ip, tsocks_he_addr, sizeof(tsocks_he_addr));
	if (!ret_str) {
		PERROR("inet_ntop");
		h_errno = NO_ADDRESS;
		goto error;
	}

	tsocks_he_addr_list[0] = tsocks_he_addr;
	tsocks_he_addr_list[1] = NULL;

	tsocks_he.h_name = (char *) __name;
	tsocks_he.h_aliases = NULL;
	tsocks_he.h_length = sizeof(in_addr_t);
	tsocks_he.h_addrtype = AF_INET;
	tsocks_he.h_addr_list = tsocks_he_addr_list;

	DBG("Hostname %s resolved to %s", __name, tsocks_he_addr);

	errno = 0;
	return &tsocks_he;

error:
	return NULL;
}

/*
 * Libc hijacked symbol gethostbyname(3).
 */
LIBC_GETHOSTBYNAME_DECL
{
	return tsocks_gethostbyname(LIBC_GETHOSTBYNAME_ARGS);
}
