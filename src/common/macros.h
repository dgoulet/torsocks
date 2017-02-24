/*
 * Copyright (c) 2009 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *               2013 - David Goulet <dgoulet@ev0ke.net>
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

#ifndef TORSOCKS_MACROS_H
#define TORSOCKS_MACROS_H

#include <stddef.h> /* for offsetof */

/*
 * container_of - Get the address of an object containing a field.
 *
 * @ptr: pointer to the field.
 * @type: type of the object.
 * @member: name of the field within the object.
 */
#define container_of(ptr, type, member)                            \
    ({                                                             \
        const __typeof__(((type *) NULL)->member) * __ptr = (ptr); \
        (type *)((char *)__ptr - offsetof(type, member));          \
    })

/* Memory allocation zeroed. */
#define zmalloc(x) calloc(1, x)

#ifndef ATTR_HIDDEN
#define ATTR_HIDDEN __attribute__((visibility("hidden")))
#endif

#ifndef ATTR_UNUSED
#define ATTR_UNUSED __attribute__ ((unused))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#endif /* TORSOCKS_MACROS_H */
