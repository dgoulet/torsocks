/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org>
 *               2008-2011 - Robert Hogan <robert@roberthogan.net>
 *               2013 - David Goulet <dgoulet@ev0ke.net>
 *                      Luke Gallagher <luke@hypergeometric.net>
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

#ifndef FIXTURES_H
#define FIXTURES_H

#include <string.h>

#if !defined(TORSOCKS_FIXTURE_PATH)
#define TORSOCKS_FIXTURE_PATH	0
#endif /* TORSOCKS_FIXTURE_PATH */

static const char *fixture_path(const char *base, const char *filename)
{
	static char path[1024];
	size_t path_len;

	path_len = strlen(base);
	strncpy(path, base, path_len);
	strncpy(path + path_len, filename, sizeof(path) - path_len);

	return path;
}

const char *fixture(const char *fixture_name)
{
	return fixture_path(TORSOCKS_FIXTURE_PATH, fixture_name);
}

#endif /* FIXTURES_H */
