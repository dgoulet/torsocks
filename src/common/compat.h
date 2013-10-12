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

#if defined(__linux__)

#if defined(__i386)
#include <asm-generic/unistd.h>
#else
#include <unistd.h>
#endif /* defined __i386 */

#include <sys/syscall.h>

/*
 * Some old system requires kernel headers for those values. If they are not
 * defined, set them to a non syscall value. Just to be clear, if the value is
 * undefined (here -1), tsocks syscall() will DENY the real syscall if catched.
 */
#ifndef __NR_socket
#define __NR_socket -1
#endif
#ifndef __NR_connect
#define __NR_connect -1
#endif
#ifndef __NR_close
#define __NR_close -1
#endif

#define TSOCKS_NR_SOCKET    __NR_socket
#define TSOCKS_NR_CONNECT   __NR_connect
#define TSOCKS_NR_CLOSE     __NR_close

#endif /* __linux__ */

#if (defined(__FreeBSD__) || defined(__darwin__))

#include <sys/syscall.h>
#include <unistd.h>

#define TSOCKS_NR_SOCKET    SYS_socket
#define TSOCKS_NR_CONNECT   SYS_connect
#define TSOCKS_NR_CLOSE     SYS_close

#endif /* __FreeBSD__, __darwin__ */

#endif /* TORSOCKS_COMPAT_H */
