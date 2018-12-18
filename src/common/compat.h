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

#if (defined(__linux__) || defined(__GLIBC__) || defined(__FreeBSD__) || \
		defined(__darwin__) || defined(__NetBSD__))

#ifndef RTLD_NEXT
#define RTLD_NEXT	((void *) -1)
#endif

#include <pthread.h>

typedef struct tsocks_mutex_t {
	pthread_mutex_t mutex;
} tsocks_mutex_t;

/* Define a tsock mutex variable with the mutex statically initialized. */
#define TSOCKS_MUTEX_INIT { .mutex = PTHREAD_MUTEX_INITIALIZER }
#define TSOCKS_INIT_MUTEX(name) \
	tsocks_mutex_t name = TSOCKS_MUTEX_INIT

void tsocks_mutex_init(tsocks_mutex_t *m);
void tsocks_mutex_destroy(tsocks_mutex_t *m);
void tsocks_mutex_lock(tsocks_mutex_t *m);
void tsocks_mutex_unlock(tsocks_mutex_t *m);

typedef struct tsocks_once_t {
	int once:1;
	tsocks_mutex_t mutex;
} tsocks_once_t;

/* Define a tsock once variable, statically initialized. */
#define TSOCKS_INIT_ONCE(name) \
	tsocks_once_t name = { .once = 1, .mutex = TSOCKS_MUTEX_INIT }

void tsocks_once(tsocks_once_t *o, void (*init_routine)(void));

#else
#error "OS not supported."
#endif /* __linux__, __GLIBC__, __darwin__, __FreeBSD__, __NetBSD__ */

#if defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>

/*
 * Some old system requires kernel headers for those values. If they are not
 * defined, set them to a bad syscall value. Just to be clear, if the value is
 * undefined, tsocks syscall() will DENY the real syscall if caught.
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
#ifndef __NR_gettid
#define __NR_gettid -10
#endif
#ifndef __NR_getrandom
#define __NR_getrandom -11
#endif
#ifndef __NR_futex
#define __NR_futex -12
#endif
#ifndef __NR_accept4
#define __NR_accept4 -13
#endif
#ifndef __NR_sched_getaffinity
#define __NR_sched_getaffinity -14
#endif
#ifndef __NR_seccomp
#define __NR_seccomp -15
#endif
#ifndef __NR_gettimeofday
#define __NR_gettimeofday -16
#endif
#ifndef __NR_clock_gettime
#define __NR_clock_gettime -17
#endif
#ifndef __NR_fork
#define __NR_fork -18
#endif
#ifndef __NR_memfd_create
#define __NR_memfd_create -19
#endif
#ifndef __NR_getdents
#define __NR_getdents -20
#endif
#ifndef __NR_getdents64
#define __NR_getdents64 -21
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
#define TSOCKS_NR_GETTID    __NR_gettid
#define TSOCKS_NR_GETRANDOM __NR_getrandom
#define TSOCKS_NR_FUTEX     __NR_futex
#define TSOCKS_NR_ACCEPT4   __NR_accept4
#define TSOCKS_NR_SCHED_GETAFFINITY __NR_sched_getaffinity
#define TSOCKS_NR_SECCOMP   __NR_seccomp
#define TSOCKS_NR_GETTIMEOFDAY __NR_gettimeofday
#define TSOCKS_NR_CLOCK_GETTIME __NR_clock_gettime
#define TSOCKS_NR_FORK      __NR_fork
#define TSOCKS_NR_MEMFD_CREATE __NR_memfd_create
#define TSOCKS_NR_GETDENTS __NR_getdents
#define TSOCKS_NR_GETDENTS64 __NR_getdents64

/*
 * Despite glibc providing wrappers for these calls for a long time
 * (as in "even Debian squeeze has all the wrappers"), libuv decided to
 * use syscall() to invoke them instead.
 */

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>

#ifndef __NR_epoll_create1
#define __NR_epoll_create1 -128
#endif
#ifndef __NR_epoll_wait
#define __NR_epoll_wait -129
#endif
#ifndef __NR_epoll_pwait
#define __NR_epoll_pwait -130
#endif
#ifndef __NR_epoll_ctl
#define __NR_epoll_ctl -131
#endif
#ifndef __NR_eventfd2
#define __NR_eventfd2 -132
#endif
#ifndef __NR_inotify_init1
#define __NR_inotify_init1 -133
#endif
#ifndef __NR_inotify_add_watch
#define __NR_inotify_add_watch -134
#endif
#ifndef __NR_inotify_rm_watch
#define __NR_inotify_rm_watch -135
#endif

#define TSOCKS_NR_EPOLL_CREATE1 __NR_epoll_create1
#define TSOCKS_NR_EPOLL_WAIT    __NR_epoll_wait
#define TSOCKS_NR_EPOLL_PWAIT   __NR_epoll_pwait
#define TSOCKS_NR_EPOLL_CTL     __NR_epoll_ctl
#define TSOCKS_NR_EVENTFD2      __NR_eventfd2
#define TSOCKS_NR_INOTIFY_INIT1 __NR_inotify_init1
#define TSOCKS_NR_INOTIFY_ADD_WATCH __NR_inotify_add_watch
#define TSOCKS_NR_INOTIFY_RM_WATCH  __NR_inotify_rm_watch

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
#define IS_SOCK_DGRAM(type) \
	((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC | SOCK_NOSIGPIPE)) == SOCK_DGRAM)
#else /* __NetBSD__ */
#define IS_SOCK_STREAM(type) \
	((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_STREAM)
#define IS_SOCK_DGRAM(type) \
	((type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) == SOCK_DGRAM)
#endif /* __NetBSD__ */

#endif /* TORSOCKS_COMPAT_H */
