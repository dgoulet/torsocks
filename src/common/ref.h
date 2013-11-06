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

#ifndef TORSOCKS_REF_H
#define TORSOCKS_REF_H

#include <assert.h>

#include "compat.h"

struct ref {
	long count;
};

#if (defined(__GLIBC__) || defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))

/*
 * Get a reference by incrementing the refcount.
 */
static inline void ref_get(struct ref *r)
{
	(void) __sync_add_and_fetch(&r->count, 1);
}

/*
 * Put a reference back by decrementing the refcount.
 *
 * The release function MUST use container_of to get back the object pointer in
 * which the ref structure is located.
 */
static inline void ref_put(struct ref *r,
		void (*release)(struct ref *))
{
	long ret;

	assert(release);
	ret = __sync_sub_and_fetch(&r->count, 1);
	assert(ret >= 0);
	if (ret == 0) {
		release(r);
	}
}

#else
#error "OS not supported"
#endif /* __GLIBC__, __FreeBSD__, __darwin__ */

#endif /* TORSOCKS_REF_H */
