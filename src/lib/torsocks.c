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

#include <common/defaults.h>
#include <common/log.h>

#include "torsocks.h"

/*
 * Set to 1 if the binary is set with suid or 0 if not. This is set once during
 * initialization so after that it can be read without any protection.
 */
static int is_suid;

/*
 * Lookup symbol in the loaded libraries of the binary.
 *
 * Return the function pointer or NULL on error.
 */
static void *find_libc_symbol(const char *symbol)
{
	void *fct_ptr = NULL;

	assert(symbol);

	fct_ptr = dlsym(RTLD_NEXT, symbol);
	if (!fct_ptr) {
		ERR("Unable to find %s", symbol);
		goto end;
	}

end:
	return fct_ptr;
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
static void __attribute__((constructor)) init()
{
	/* UID and effective UID MUST be the same or else we are SUID. */
	is_suid = (getuid() != geteuid());

	init_logging();
}

/*
 * Cleanup and exit with the given status.
 */
static void clean_exit(int status)
{
	exit(status);
}

/*
 * Libc hijacked symbol connect(2).
 */
int connect(LIBC_CONNECT_SIG)
{
	static int (*libc_connect)(LIBC_CONNECT_SIG) = NULL;

	/* Find symbol if not already set. */
	if (!libc_connect) {
		libc_connect = find_libc_symbol("connect");
		if (!libc_connect) {
			ERR("This is critical for torsocks. Exiting");
			clean_exit(EXIT_FAILURE);
		}
	}

	return libc_connect(_sockfd, _addr, _addrlen);
}
