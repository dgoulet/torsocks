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

#ifndef TORSOCKS_COMPAT_H
#define TORSOCKS_COMPAT_H

#if (defined(__APPLE__) && defined(__MACH__) && !defined(__darwin__))
#define __darwin__	1
#endif

#if (defined(__linux__) || defined(__FreeBSD__) || defined(__darwin__))

#define RTLD_NEXT	((void *) -1)

#include <pthread.h>

typedef struct tsocks_mutex_t {
	pthread_mutex_t mutex;
} tsocks_mutex_t;

/* Define a tsock mutex variable with the mutex statically initialized. */
#define TSOCKS_INIT_MUTEX(name) \
	tsocks_mutex_t name = { .mutex = PTHREAD_MUTEX_INITIALIZER }

void tsocks_mutex_init(tsocks_mutex_t *m);
void tsocks_mutex_destroy(tsocks_mutex_t *m);
void tsocks_mutex_lock(tsocks_mutex_t *m);
void tsocks_mutex_unlock(tsocks_mutex_t *m);

#endif /* __linux__, __darwin__, __FreeBSD__ */

#endif /* TORSOCKS_COMPAT_H */
