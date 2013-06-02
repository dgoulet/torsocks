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

#define MSGNONE   -1
#define MSGERR    0
#define MSGWARN   1
#define MSGTEST  2
#define MSGNOTICE 3
#define MSGDEBUG  3

int loglevel = MSGERR;    /* The default logging level is to only log
							 error messages */
char logfilename[256];    /* Name of file to which log messages should
							 be redirected */
FILE *logfile;     /* File to which messages should be logged */
int logstamp;         /* Timestamp (and pid stamp) messages */

void set_log_options(int level, char *filename, int timestamp);
void show_msg(int level, const char *fmt, ...);

#endif /* TORSOCKS_LOG_H */
