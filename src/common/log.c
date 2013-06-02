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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


#include "log.h"

/* Set logging options, the options are as follows:             */
/*  level - This sets the logging threshold, messages with      */
/*          a higher level (i.e lower importance) will not be   */
/*          output. For example, if the threshold is set to     */
/*          MSGWARN a call to log a message of level MSGDEBUG   */
/*          would be ignored. This can be set to -1 to disable  */
/*          messages entirely                                   */
/*  filename - This is a filename to which the messages should  */
/*             be logged instead of to standard error           */
/*  timestamp - This indicates that messages should be prefixed */
/*              with timestamps (and the process id)            */
void set_log_options(int level, char *filename, int timestamp)
{
	loglevel = level;
	if (loglevel < MSGERR)
		loglevel = MSGNONE;

	if (filename) {
		strncpy(logfilename, filename, sizeof(logfilename));
		logfilename[sizeof(logfilename) - 1] = '\0';
	}

	logstamp = timestamp;
}

void show_msg(int level, const char *fmt, ...)
{
	va_list ap;
	int saveerr;
	extern char *torsocks_progname;
	char timestring[20];
	time_t timestamp;

	if ((loglevel == MSGNONE) || (level > loglevel))
		return;

	if (!logfile) {
		if (logfilename[0]) {
			logfile = fopen(logfilename, "a");
			if (logfile == NULL) {
				logfile = stderr;
				show_msg(MSGERR, "Could not open log file, %s, %s\n", 
						logfilename, strerror(errno));
			}
		} else
			logfile = stderr;
	}

	if (logstamp) {
		timestamp = time(NULL);
		strftime(timestring, sizeof(timestring),  "%H:%M:%S", 
				localtime(&timestamp));
		fprintf(logfile, "%s ", timestring);
	}

	fputs(torsocks_progname, logfile);

	if (logstamp) {
		fprintf(logfile, "(%d)", getpid());
	}

	fputs(": ", logfile);

	va_start(ap, fmt);

	/* Save errno */
	saveerr = errno;

	vfprintf(logfile, fmt, ap);

	fflush(logfile);

	errno = saveerr;

	va_end(ap);
}

