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

#include "log.h"

#define DEFAULT_TOR_PORT	9050
#define DEFAULT_TOR_ADDRESS	"127.0.0.1"
#define DEFAULT_TOR_SOCKS	5

/* Logging defaults. */
#define DEFAULT_LOG_LEVEL_ENV		"TORSOCKS_LOG_LEVEL"
#define DEFAULT_LOG_TIME_ENV		"TORSOCKS_LOG_TIME"
#define DEFAULT_LOG_FILEPATH_ENV	"TORSOCKS_LOG_FILE_PATH"
#define DEFAULT_LOG_TIME_STATUS		LOG_TIME_ADD
#define DEFAULT_LOG_LEVEL			MSGWARN

#endif /* TORSOCKS_DEFAULTS_H */
