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

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "defaults.h"
#include "macros.h"

static struct log_config {
	FILE *fp;
	char *filepath;
	/* Add time or not to the log entry. */
	enum log_time_status time_status;
} logconfig;

/*
 * The default logging level is to only log error messages.
 */
int tsocks_loglevel = DEFAULT_LOG_LEVEL;

/*
 * Add a special formatted timestamp at the beginning of the given buffer.
 *
 * On success, return the number of bytes written else, return 0.
 */
static size_t add_time_to_log(char *buf, size_t len)
{
	time_t now;
	const struct tm *tm;

	assert(buf);

	/* Get time stamp. */
	time(&now);
	tm = localtime(&now);
	return strftime(buf, len, "[%b %d %H:%M:%S] ", tm);
}

/*
 * Log function taking a format and variable number of arguments fitting the
 * given format.
 */
static void _log_write(char *buf, size_t len)
{
    int ret;

    assert(buf);
	assert(logconfig.fp);

	/* Make sure buffer is NULL terminated. */
	buf[len - 1] = '\0';

    ret = fprintf(logconfig.fp, "%s", buf);
    if (ret < 0) {
        fprintf(stderr, "[tsocks] logging failed. Stopping logging.\n");
        log_destroy();
        goto end;
    }

    /*
     * On a write failure we stop the logging but a flush failure is not that
     * critical.
     */
    (void) fflush(logconfig.fp);

end:
    return;
}

/*
 * Log messages using the logconfig configuration.
 */
ATTR_HIDDEN
void log_print(const char *fmt, ...)
{
	int ret;
	size_t written = 0;
	va_list ap;
	/* This is a hard limit for the size of the line. */
	char buf[4096];

	assert(fmt);

	if (!logconfig.fp) {
		goto end;
	}

	memset(buf, 0, sizeof(buf));
	va_start(ap, fmt);

	if (logconfig.time_status == LOG_TIME_ADD) {
		written = add_time_to_log(buf, sizeof(buf));
	}

	ret = vsnprintf(buf + written, sizeof(buf) - written, fmt, ap);
	if (ret < 0) {
		perror("[tsocks] vsnprintf log");
		goto error;
	}

	_log_write(buf, sizeof(buf));

error:
	va_end(ap);
end:
	return;
}

/*
 * Initialize logconfig.
 *
 * Return 0 on success or else a negative errno value.
 */
ATTR_HIDDEN
int log_init(int level, const char *filepath, enum log_time_status t_status)
{
	int ret = 0;

	/* Reset logconfig. Useful if this is called multiple times. */
	memset(&logconfig, 0, sizeof(logconfig));

	if (level < MSGNONE || level > MSGDEBUG) {
		fprintf(stderr, "[tsocks] Unknown loglevel %d\n", level);
		ret = -ENOENT;
		goto error;
	}

	if (filepath) {
		logconfig.fp = fopen(filepath, "a");
		if (!logconfig.fp) {
			fprintf(stderr, "[tsocks] Unable to open log file %s\n", filepath);
			ret = -errno;
			goto error;
		}

		logconfig.filepath = strdup(filepath);
		if (!logconfig.filepath) {
			perror("[tsocks] log init strdup");
			ret = -errno;
			fclose(logconfig.fp);
			goto error;
		}
	} else {
		/* The default output is stderr if no filepath is given. */
		ret = fileno(stderr);
		if (ret >= 0 && errno != EBADF) {
			logconfig.fp = stderr;
			ret = 0;
		}
	}

	tsocks_loglevel = level;
	logconfig.time_status = t_status;

error:
	return ret;
}

/*
 * Cleanup the logconfig data structure.
 */
ATTR_HIDDEN
void log_destroy(void)
{
	free(logconfig.filepath);
	if (logconfig.fp) {
		int ret;

		ret = fclose(logconfig.fp);
		if (ret) {
			perror("[tsocks] fclose log destroy");
		}
	}
}
