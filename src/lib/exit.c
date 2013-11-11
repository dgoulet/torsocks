/*
 * Copyright (C) - 2013 - David Goulet <dgoulet@ev0ke.net>
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

#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>

#include "torsocks.h"

/*
 * _exit() and _Exit are hijacked here so we can cleanup torsocks library
 * safely since the destructor is *not* called for these functions.
 */

void _exit(int status)
{
	static void (*plibc_func)(int) = NULL;

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "_exit");
		if (plibc_func == NULL) {
			ERR("unable to find \"_exit\" symbol");
			errno = ENOSYS;
		}
	}

	tsocks_cleanup();

	if (plibc_func) {
		plibc_func(status);
	}

	/*
	 * This should never be reached but for the sake of the compiler
	 * not complaining, this function MUST never return.
	 */
	abort();
}

void _Exit(int status)
{
	static void (*plibc_func)(int) = NULL;

	if (plibc_func == NULL) {
		plibc_func = dlsym(RTLD_NEXT, "_Exit");
		if (plibc_func == NULL) {
			ERR("unable to find \"_Exit\" symbol");
			errno = ENOSYS;
		}
	}

	tsocks_cleanup();

	if (plibc_func) {
		plibc_func(status);
	}

	/*
	 * This should never be reached but for the sake of the compiler
	 * not complaining, this function MUST never return.
	 */
	abort();
}
