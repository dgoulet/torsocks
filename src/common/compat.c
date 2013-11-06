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

#include "compat.h"

#if (defined(__GLIBC__) || defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))

/*
 * Initialize a pthread mutex. This never fails.
 */
void tsocks_mutex_init(tsocks_mutex_t *m)
{
	assert(m);
	pthread_mutex_init(&m->mutex, NULL);
}

/*
 * Destroy a pthread mutex. This never fails.
 */
void tsocks_mutex_destroy(tsocks_mutex_t *m)
{
	assert(m);
	pthread_mutex_destroy(&m->mutex);
}

/*
 * Use pthread mutex lock and assert on any error.
 */
void tsocks_mutex_lock(tsocks_mutex_t *m)
{
	int ret;

	assert(m);
	ret = pthread_mutex_lock(&m->mutex);
	/*
	 * Unable to lock the mutex could lead to undefined behavior and potential
	 * security issues. Stop everything so torsocks can't continue.
	 */
	assert(!ret);
}

/*
 * Use pthread mutex unlock and assert on any error.
 */
void tsocks_mutex_unlock(tsocks_mutex_t *m)
{
	int ret;

	assert(m);
	ret = pthread_mutex_unlock(&m->mutex);
	/*
	 * Unable to unlock the mutex could lead to undefined behavior and potential
	 * security issues. Stop everything so torsocks can't continue.
	 */
	assert(!ret);
}

#endif /* __GLIBC__, __darwin__, __FreeBSD__, __NetBSD__ */
