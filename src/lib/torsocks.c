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
#include <inttypes.h>
#include <stdlib.h>

#include <common/config-file.h>
#include <common/connection.h>
#include <common/defaults.h>
#include <common/log.h>
#include <common/onion.h>
#include <common/socks5.h>
#include <common/utils.h>

#include "torsocks.h"

/*
 * Global configuration of torsocks taken from the configuration file or set
 * with the defaults. This is initialized in the constructor once and only
 * once. Once done, this object is *immutable* thus no locking is needed to
 * read this object as long as there is not write action.
 */
struct configuration tsocks_config;

/*
 * This is the onion address pool for the library. It is initialized once in
 * the constructor. This object changes over time and every access is nested
 * inside the registry lock.
 */
struct onion_pool tsocks_onion_pool;

/* Indicate if the library was initialized previously. */
static TSOCKS_INIT_ONCE(init_once);

/* Indicate if the library was cleaned up previously. */
static TSOCKS_INIT_ONCE(term_once);

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
 * Read SOCKS5 username and password environment variable and if found set them
 * in the configuration. If we are setuid, return gracefully.
 */
static void read_env(void)
{
	int ret;
	const char *username, *password, *allow_in, *isolate_pid, *tor_address, *tor_port;

	if (is_suid) {
		goto end;
	}

	allow_in = getenv(DEFAULT_ALLOW_INBOUND_ENV);
	if (allow_in) {
		ret = conf_file_set_allow_inbound(allow_in, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

	isolate_pid = getenv(DEFAULT_ISOLATE_PID_ENV);
	if (isolate_pid) {
		ret = conf_file_set_isolate_pid(isolate_pid, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

	tor_address = getenv(DEFAULT_TOR_ADDRESS_ENV);
	if (tor_address) {
		ret = conf_file_set_tor_address(tor_address, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

	tor_port = getenv(DEFAULT_TOR_PORT_ENV);
	if (tor_port) {
		ret = conf_file_set_tor_port(tor_port, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

	username = getenv(DEFAULT_SOCKS5_USER_ENV);
	password = getenv(DEFAULT_SOCKS5_PASS_ENV);
	if (!username && !password) {
		goto end;
	}

	/*
	 * Only set the values if they were provided. It's possible that a user
	 * wants to only set one of the values through an env. variable and the
	 * other through the configuration file.
	 */
	if (username) {
		ret = conf_file_set_socks5_user(username, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

	if (password) {
		ret = conf_file_set_socks5_pass(password, &tsocks_config);
		if (ret < 0) {
			goto error;
		}
	}

end:
	return;
error:
	/*
	 * Error while setting user/pass variable. Stop everything so the user can
	 * be notified and fix the issue.
	 */
	clean_exit(EXIT_FAILURE);
}

/*
 * Initialize torsocks configuration from a given conf file or the default one.
 */
static void init_config(void)
{
	int ret;
	const char *filename = NULL;

	if (!is_suid) {
		filename = getenv(DEFAULT_CONF_FILE_ENV);
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
		ret = conf_file_set_tor_address(DEFAULT_TOR_ADDRESS, &tsocks_config);
		if (ret < 0) {
			/* Most likely ENOMEM thus we can't continue. */
			clean_exit(EXIT_FAILURE);
		}
	}
	if (tsocks_config.conf_file.tor_port == 0) {
		tsocks_config.conf_file.tor_port = DEFAULT_TOR_PORT;
	}
	if (tsocks_config.conf_file.tor_domain == 0) {
		tsocks_config.conf_file.tor_domain = DEFAULT_TOR_DOMAIN;
	}
	if (tsocks_config.conf_file.onion_base == 0) {
		tsocks_config.conf_file.onion_base = inet_addr(DEFAULT_ONION_ADDR_RANGE);
		tsocks_config.conf_file.onion_mask = atoi(DEFAULT_ONION_ADDR_MASK);
	}

	/* Handle possible env. variables. */
	read_env();

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

	/* Finalize the SOCKS auth (Isolation) settings. */
	ret = conf_apply_socks_auth(&tsocks_config);
	if (ret < 0) {
		clean_exit(EXIT_FAILURE);
	}
}

/*
 * Save all the original libc function calls that torsocks needs.
 */
static void init_libc_symbols(void)
{
	int ret;
	void *libc_ptr;

	dlerror();
	libc_ptr = dlopen(LIBC_NAME, RTLD_LAZY);
	if (!libc_ptr) {
		ERR("Unable to dlopen() library " LIBC_NAME "(%s)", dlerror());
		goto error_dlopen;
	}

	dlerror();
	tsocks_libc_connect = dlsym(libc_ptr, LIBC_CONNECT_NAME_STR);
	tsocks_libc_close = dlsym(libc_ptr, LIBC_CLOSE_NAME_STR);
	tsocks_libc_socket = dlsym(libc_ptr, LIBC_SOCKET_NAME_STR);
	tsocks_libc_syscall = dlsym(libc_ptr, LIBC_SYSCALL_NAME_STR);
	tsocks_libc_execve = dlsym(libc_ptr, LIBC_EXECVE_NAME_STR);
	tsocks_libc_accept4 = dlsym(libc_ptr, LIBC_ACCEPT4_NAME_STR);
	if (!tsocks_libc_connect || !tsocks_libc_close || !tsocks_libc_socket ||
			!tsocks_libc_syscall || !tsocks_libc_execve || ! tsocks_libc_accept4) {
		ERR("Unable to lookup symbols in " LIBC_NAME "(%s)", dlerror());
		goto error;
	}

	ret = dlclose(libc_ptr);
	if (ret != 0) {
		ERR("dlclose: %s", dlerror());
	}
	return;

error:
	ret = dlclose(libc_ptr);
	if (ret != 0) {
		ERR("dlclose: %s", dlerror());
	}
error_dlopen:
	clean_exit(EXIT_FAILURE);
}

/*
 * Initialize logging subsystem using either the default values or the one given
 * by the environment variables.
 */
static void init_logging(void)
{
	int level;
	const char *filepath = NULL, *level_str = NULL, *time_status_str = NULL;
	enum log_time_status t_status;

	/* Get log level from user or use default. */
	if (!is_suid) {
		level_str = getenv(DEFAULT_LOG_LEVEL_ENV);
	}
	if (level_str) {
		level = atoi(level_str);
	} else {
		/* Set to the default loglevel. */
		level = tsocks_loglevel;
	}

	/* Get time status from user or use default. */
	if (!is_suid) {
		time_status_str = getenv(DEFAULT_LOG_TIME_ENV);
	}
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

	DBG("Logging subsystem initialized. Level %d, file %s, time %d",
			level, filepath, t_status);
}

/*
 * Lib constructor. Initialize torsocks here before the main execution of the
 * binary we are preloading.
 */
static void tsocks_init(void)
{
	int ret;

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

	/*
	 * Initalized the onion pool which maps cookie address to hidden service
	 * onion address.
	 */
	ret = onion_pool_init(&tsocks_onion_pool,
			tsocks_config.conf_file.onion_base,
			tsocks_config.conf_file.onion_mask);
	if (ret < 0) {
		clean_exit(EXIT_FAILURE);
	}
}

/*
 * Lib destructor.
 */
static void tsocks_exit(void)
{
	/* Cleanup every entries in the onion pool. */
	onion_pool_destroy(&tsocks_onion_pool);
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
static int setup_tor_connection(struct connection *conn,
		uint8_t socks5_method)
{
	int ret;

	assert(conn);

	DBG("Setting up a connection to the Tor network on fd %d", conn->fd);

	ret = socks5_connect(conn);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_send_method(conn, socks5_method);
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
 * Lookup by hostname for an onion entry in a given pool. The entry is returned
 * if found or else a new one is created, added to the pool and finally
 * returned.
 *
 * NOTE: The pool lock MUST NOT be acquired before calling this.
 *
 * On success the entry is returned else a NULL value.
 */
static struct onion_entry *get_onion_entry(const char *hostname,
		struct onion_pool *pool)
{
	struct onion_entry *entry = NULL;

	assert(hostname);
	assert(pool);

	tsocks_mutex_lock(&pool->lock);

	entry = onion_entry_find_by_name(hostname, pool);
	if (entry) {
		goto end;
	}

	/*
	 * On success, the onion entry is automatically added to the onion pool and
	 * the reference is returned.
	 */
	entry = onion_entry_create(pool, hostname);
	if (!entry) {
		goto error;
	}

end:
error:
	tsocks_mutex_unlock(&pool->lock);
	return entry;
}

/*
 * Using the given connection, do a SOCKS5 authentication with the
 * username/password in the global configuration.
 *
 * Return 0 on success else a negative value on error.
 */
static int
auth_socks5(struct connection *conn)
{
	int ret;

	assert(conn);

	ret = socks5_send_user_pass_request(conn,
			tsocks_config.conf_file.socks5_username,
			tsocks_config.conf_file.socks5_password);
	if (ret < 0) {
		goto error;
	}

	ret = socks5_recv_user_pass_reply(conn);
	if (ret < 0) {
		goto error;
	}

error:
	return ret;
}

/*
 * Initiate a SOCK5 connection to the Tor network using the given connection.
 * The socks5 API will use the torsocks configuration object to find the tor
 * daemon. If a username/password has been set use that method for the SOCKS5
 * connection.
 *
 * Return 0 on success or else a negative value being the errno value that
 * needs to be sent back.
 */
int tsocks_connect_to_tor(struct connection *conn)
{
	int ret;
	uint8_t socks5_method;

	assert(conn);

	DBG("Connecting to the Tor network on fd %d", conn->fd);

	/* Is this configuration is set to use SOCKS5 authentication. */
	if (tsocks_config.socks5_use_auth) {
		socks5_method = SOCKS5_USER_PASS_METHOD;
	} else {
		socks5_method = SOCKS5_NO_AUTH_METHOD;
	}

	ret = setup_tor_connection(conn, socks5_method);
	if (ret < 0) {
		goto error;
	}

	/* For the user/pass method, send the request before connect. */
	if (socks5_method == SOCKS5_USER_PASS_METHOD) {
		ret = auth_socks5(conn);
		if (ret < 0) {
			goto error;
		}
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
int tsocks_tor_resolve(int af, const char *hostname, void *ip_addr)
{
	int ret;
	size_t addr_len;
	struct connection conn;
	uint8_t socks5_method;

	assert(hostname);
	assert(ip_addr);

	if (af == AF_INET) {
		addr_len = sizeof(uint32_t);
		conn.dest_addr.domain = CONNECTION_DOMAIN_INET;
	} else if (af == AF_INET6) {
		addr_len = 16;
		conn.dest_addr.domain = CONNECTION_DOMAIN_INET6;
		/* Tor daemon does not support IPv6 DNS resolution yet. */
		ret = -ENOSYS;
		goto error;
	} else {
		ret = -EINVAL;
		goto error;
	}

	ret = utils_localhost_resolve(hostname, af, ip_addr, addr_len);
	if (ret) {
		/* Found to be a localhost name. */
		ret = 0;
		goto end;
	}

	DBG("Resolving %s on the Tor network", hostname);

	/*
	 * Tor hidden service address have no IP address so we send back an onion
	 * reserved IP address that acts as a cookie that we will use to find the
	 * onion hostname at the connect() stage.
	 */
	if (utils_strcasecmpend(hostname, ".onion") == 0) {
		struct onion_entry *entry;

		entry = get_onion_entry(hostname, &tsocks_onion_pool);
		if (entry) {
			memcpy(ip_addr, &entry->ip, sizeof(entry->ip));
			ret = 0;
			goto end;
		}
	}

	conn.fd = tsocks_libc_socket(af, SOCK_STREAM, IPPROTO_TCP);
	if (conn.fd < 0) {
		PERROR("socket");
		ret = -errno;
		goto error;
	}

	/* Is this configuration is set to use SOCKS5 authentication. */
	if (tsocks_config.socks5_use_auth) {
		socks5_method = SOCKS5_USER_PASS_METHOD;
	} else {
		socks5_method = SOCKS5_NO_AUTH_METHOD;
	}

	ret = setup_tor_connection(&conn, socks5_method);
	if (ret < 0) {
		goto end_close;
	}

	/* For the user/pass method, send the request before resolve. */
	if (socks5_method == SOCKS5_USER_PASS_METHOD) {
		ret = auth_socks5(&conn);
		if (ret < 0) {
			goto end_close;
		}
	}

	ret = socks5_send_resolve_request(hostname, &conn);
	if (ret < 0) {
		goto end_close;
	}

	/* Force IPv4 resolution for now. */
	ret = socks5_recv_resolve_reply(&conn, ip_addr, addr_len);
	if (ret < 0) {
		goto end_close;
	}

end_close:
	if (tsocks_libc_close(conn.fd) < 0) {
		PERROR("close");
	}
end:
error:
	return ret;
}

/*
 * Resolve a hostname through Tor and set the ip address in the given pointer.
 *
 * Return 0 on success else a negative value and the result addr is untouched.
 */
int tsocks_tor_resolve_ptr(const char *addr, char **ip, int af)
{
	int ret;
	struct connection conn;
	uint8_t socks5_method;

	assert(addr);
	assert(ip);

	DBG("Resolving %" PRIu32 " on the Tor network", addr);

	conn.fd = tsocks_libc_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (conn.fd < 0) {
		PERROR("socket");
		ret = -errno;
		goto error;
	}
	conn.dest_addr.domain = CONNECTION_DOMAIN_INET;

	/* Is this configuration is set to use SOCKS5 authentication. */
	if (tsocks_config.socks5_use_auth) {
		socks5_method = SOCKS5_USER_PASS_METHOD;
	} else {
		socks5_method = SOCKS5_NO_AUTH_METHOD;
	}

	ret = setup_tor_connection(&conn, socks5_method);
	if (ret < 0) {
		goto end_close;
	}

	/* For the user/pass method, send the request before resolve ptr. */
	if (socks5_method == SOCKS5_USER_PASS_METHOD) {
		ret = auth_socks5(&conn);
		if (ret < 0) {
			goto end_close;
		}
	}

	ret = socks5_send_resolve_ptr_request(&conn, addr, af);
	if (ret < 0) {
		goto end_close;
	}

	/* Force IPv4 resolution for now. */
	ret = socks5_recv_resolve_ptr_reply(&conn, ip);
	if (ret < 0) {
		goto end_close;
	}

end_close:
	if (tsocks_libc_close(conn.fd) < 0) {
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

/*
 * Initialize torsocks library.
 */
void __attribute__((constructor)) tsocks_initialize(void)
{
	tsocks_once(&init_once, &tsocks_init);
}

/*
 * Cleanup torsocks library memory and open fd.
 */
void __attribute__((destructor)) tsocks_cleanup(void)
{
	tsocks_once(&term_once, &tsocks_exit);
}
