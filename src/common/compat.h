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

#if (defined(__GLIBC__) || defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))

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

#else
#error "OS not supported."
#endif /* __GLIBC__, __darwin__, __FreeBSD__, __NetBSD__ */

#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>

/*
 * Some old system requires kernel headers for those values. If they are not
 * defined, set them to a bad syscall value. Just to be clear, if the value is
 * undefined, tsocks syscall() will DENY the real syscall if catched.
 *
 * The values are not the same per syscall here so we don't end up with
 * duplicates in the switch case in the tsocks sycall wrapper.
 */
#ifndef __NR_socket
#define __NR_socket -1
#endif
#ifndef __NR_connect
#define __NR_connect -2
#endif
#ifndef __NR_close
#define __NR_close -3
#endif
#ifndef __NR_mmap
#define __NR_mmap -4
#endif
#ifndef __NR_munmap
#define __NR_munmap -5
#endif
#ifndef __NR_accept
#define __NR_accept -6
#endif
#ifndef __NR_getpeername
#define __NR_getpeername -7
#endif
#ifndef __NR_listen
#define __NR_listen -8
#endif
#ifndef __NR_recvmsg
#define __NR_recvmsg -9
#endif

#define TSOCKS_NR_SOCKET    __NR_socket
#define TSOCKS_NR_CONNECT   __NR_connect
#define TSOCKS_NR_CLOSE     __NR_close
#define TSOCKS_NR_MMAP      __NR_mmap
#define TSOCKS_NR_MUNMAP    __NR_munmap
#define TSOCKS_NR_ACCEPT    __NR_accept
#define TSOCKS_NR_GETPEERNAME __NR_getpeername
#define TSOCKS_NR_LISTEN    __NR_listen
#define TSOCKS_NR_RECVMSG   __NR_recvmsg

#endif /* __linux__ */

#if (defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || defined(__darwin__) || defined(__NetBSD__))

#include <sys/syscall.h>
#include <unistd.h>

#if defined(__NetBSD__)
#define SYS_socket          SYS___socket30
#endif

#define TSOCKS_NR_SOCKET    SYS_socket
#define TSOCKS_NR_CONNECT   SYS_connect
#define TSOCKS_NR_CLOSE     SYS_close
#define TSOCKS_NR_MMAP      SYS_mmap
#define TSOCKS_NR_MUNMAP    SYS_munmap
#define TSOCKS_NR_ACCEPT    SYS_accept
#define TSOCKS_NR_GETPEERNAME SYS_getpeername
#define TSOCKS_NR_LISTEN    SYS_listen
#define TSOCKS_NR_RECVMSG   SYS_recvmsg

#endif /* __FreeBSD__, __FreeBSD_kernel__, __darwin__, __NetBSD__ */

#define TSOCKS_CLASSA_NET   0xff000000
#define TSOCKS_LOOPBACK_NET 0x7f000000

/* Loopback addresses. */
#define TSOCKS_LOOPBACK     0x7f000001
#define TSOCKS_LOOPBACK6    { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 }
#define TSOCKS_ANY          ((unsigned long int) 0x00000000)
#define TSOCKS_ANY6         { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }

/*
 * Both socket flags here are defined on some BSD and Linux but not on OS X so
 * simply nullify them. Include socket.h so the constants are defined before we
 * test them.
 */
#include <sys/socket.h>
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif

/*
 * Macro to tell if a given socket type is a SOCK_STREAM or not. The macro
 * resolve to 1 if yes else 0.
 */
#if defined(__NetBSD__)
#define IS_SOCK_STREAM(type) \
	((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_NOSIGPIPE)) == SOCK_STREAM)
#else /* __NetBSD__ */
#define IS_SOCK_STREAM(type) \
	((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM)
#endif /* __NetBSD__ */

#endif /* TORSOCKS_COMPAT_H */
