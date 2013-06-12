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

#ifndef TORSOCKS_LOG_H
#define TORSOCKS_LOG_H

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "compat.h"

/* Stringify the expansion of a define */
#define XSTR(d) STR(d)
#define STR(s) #s

#define MSGNONE		0x1
#define MSGERR		0x2
#define MSGWARN		0x3
#define MSGNOTICE	0x4
#define MSGDEBUG	0x5

/*
 * Used during logging initialization whether or not to add the time or
 * suppress it from a log entry.
 */
enum log_time_status {
	LOG_TIME_NONE	= 0,
	LOG_TIME_ADD	= 1,
};

extern int tsocks_loglevel;

void log_print(const char *fmt, ...);
int log_init(int level, const char *filepath, enum log_time_status t_status);
void log_destroy(void);

#define __tsocks_print(level, fmt, args...) \
	do { \
		if (level != MSGNONE && level <= tsocks_loglevel) { \
			log_print(fmt, ## args); \
		} \
	} while (0)

#define _ERRMSG(msg, type, fmt, args...) __tsocks_print(type, msg \
		" torsocks[%ld]: " fmt " (in %s() at " __FILE__ ":" XSTR(__LINE__) ")\n", \
		(long) getpid(), ## args, __func__)

#define MSG(fmt, args...) __tsocks_print(MSGNOTICE, fmt "\n", ## args)
#define ERR(fmt, args...) _ERRMSG("ERROR", MSGERR, fmt, ## args)
#define WARN(fmt, args...) _ERRMSG("WARNING", MSGWARN, fmt, ## args)
#define DBG(fmt, args...) _ERRMSG("DEBUG", MSGDEBUG, fmt, ## args)

/*
 * Local wrapper used by the PERROR() call below. Should NOT be used outside of
 * this scope.
 */
#define _PERROR(fmt, args...) _ERRMSG("PERROR", MSGERR, fmt, ## args)

#if !defined(__linux__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && !defined(_GNU_SOURCE))

/*
 * Version using XSI strerror_r.
 */
#define PERROR(call, args...) \
	do { \
		char buf[200]; \
		strerror_r(errno, buf, sizeof(buf)); \
		_PERROR(call ": %s", ## args, buf); \
	} while(0);

#else /* _POSIX_C_SOURCE */

/*
 * Version using GNU strerror_r, for linux with appropriate defines.
 */
#define PERROR(call, args...) \
	do { \
		char *buf; \
		char tmp[200]; \
		buf = strerror_r(errno, tmp, sizeof(tmp)); \
		_PERROR(call ": %s", ## args, buf); \
	} while(0);

#endif /* _POSIX_C_SOURCE */

#endif /* TORSOCKS_LOG_H */
