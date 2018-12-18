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
#include <stdarg.h>
#include <sys/mman.h>

#include <common/log.h>

#include "torsocks.h"

/* syscall(2) */
TSOCKS_LIBC_DECL(syscall, LIBC_SYSCALL_RET_TYPE, LIBC_SYSCALL_SIG)

/*
 * Handle close syscall to be called with tsocks call.
 */
static LIBC_CLOSE_RET_TYPE handle_close(va_list args)
{
	int fd;

	fd = va_arg(args, int);

	return tsocks_close(fd);
}

/*
 * Handle socket syscall to go through Tor.
 */
static LIBC_SOCKET_RET_TYPE handle_socket(va_list args)
{
	int domain, type, protocol;

	domain = va_arg(args, int);
	type = va_arg(args, int);
	protocol = va_arg(args, int);

	return tsocks_socket(domain, type, protocol);
}

/*
 * Handle connect syscall to go through Tor.
 */
static LIBC_CONNECT_RET_TYPE handle_connect(va_list args)
{
	int sockfd;
	const struct sockaddr *addr;
	socklen_t addrlen;

	sockfd = va_arg(args, int);
	addr = va_arg(args, const struct sockaddr *);
	addrlen = va_arg(args, socklen_t);

	return tsocks_connect(sockfd, addr, addrlen);
}

/*
 * Handle accept(2) syscall to go through Tor.
 */
static LIBC_ACCEPT_RET_TYPE handle_accept(va_list args)
{
	int sockfd;
	struct sockaddr *addr;
	socklen_t addrlen;

	sockfd = va_arg(args, __typeof__(sockfd));
	addr = va_arg(args, __typeof__(addr));
	addrlen = va_arg(args, __typeof__(addrlen));

	return tsocks_accept(sockfd, addr, &addrlen);
}

#if !((defined(__NetBSD__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) && defined(__x86_64))
/*
 * Handle mmap(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_mmap(va_list args)
{
	void *addr;
	size_t len;
	int prot, flags, fd;
	off_t offset;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));
	prot = va_arg(args, __typeof__(prot));
	flags = va_arg(args, __typeof__(flags));
	fd = va_arg(args, __typeof__(fd));
	offset = va_arg(args, __typeof__(offset));

	return (LIBC_SYSCALL_RET_TYPE) mmap(addr, len, prot, flags, fd, offset);
}
#endif /* __NetBSD__, __FreeBSD__, __FreeBSD_kernel__, __x86_64 */

/*
 * Handle munmap(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_munmap(va_list args)
{
	void *addr;
	size_t len;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));

	return (LIBC_SYSCALL_RET_TYPE) munmap(addr, len);
}

/*
 * Handle getpeername(2) syscall.
 */
static LIBC_GETPEERNAME_RET_TYPE handle_getpeername(va_list args)
{
	int sockfd;
	struct sockaddr *addr;
	socklen_t *addrlen;

	sockfd = va_arg(args, __typeof__(sockfd));
	addr = va_arg(args, __typeof__(addr));
	addrlen = va_arg(args, __typeof__(addrlen));

	return tsocks_getpeername(sockfd, addr, addrlen);
}

/*
 * Handle listen(2) syscall.
 */
static LIBC_LISTEN_RET_TYPE handle_listen(va_list args)
{
	int sockfd, backlog;

	sockfd = va_arg(args, __typeof__(sockfd));
	backlog = va_arg(args, __typeof__(backlog));

	return tsocks_listen(sockfd, backlog);
}

/*
 * Handle recvmsg(2) syscall.
 */
static LIBC_RECVMSG_RET_TYPE handle_recvmsg(va_list args)
{
	int sockfd, flags;
	struct msghdr *msg;

	sockfd = va_arg(args, __typeof__(sockfd));
	msg = va_arg(args, __typeof__(msg));
	flags = va_arg(args, __typeof__(flags));

	return tsocks_recvmsg(sockfd, msg, flags);
}

#if defined(__linux__)

/*
 * Handle sched_getaffinity(2) syscall.
 * NOTE: ffmpeg is one of the application that needs this one on the
 * whitelist.
 */
static LIBC_SYSCALL_RET_TYPE handle_sched_getaffinity(va_list args)
{
	pid_t pid;
	size_t cpusetsize;
	cpu_set_t *mask;

	pid = va_arg(args, __typeof__(pid));
	cpusetsize = va_arg(args, __typeof__(cpusetsize));
	mask = va_arg(args, __typeof__(mask));

	return tsocks_libc_syscall(TSOCKS_NR_SCHED_GETAFFINITY, pid, cpusetsize,
			mask);
}

/*
 * Handle gettid(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_gettid(void)
{
	return tsocks_libc_syscall(TSOCKS_NR_GETTID);
}

/*
 * Handle getrandom(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_getrandom(va_list args)
{
	void *buf;
	size_t buflen;
	unsigned int flags;

	buf = va_arg(args, __typeof__(buf));
	buflen = va_arg(args, __typeof__(buflen));
	flags = va_arg(args, __typeof__(flags));

	return tsocks_libc_syscall(TSOCKS_NR_GETRANDOM, buf, buflen, flags);
}

/*
 * Handle futex(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_futex(va_list args)
{
	/* This assumes Linux 2.6.7 or later, as that is when 'val3' was
	 * added to futex(2).  Kernel versions prior to that are what I
	 * would consider historic.
	 */
	const struct timespec *timeout;
	int *uaddr, *uaddr2;
	int op, val, val3;

	uaddr = va_arg(args, __typeof__(uaddr));
	op = va_arg(args, __typeof__(op));
	val = va_arg(args, __typeof__(val));
	timeout = va_arg(args, __typeof__(timeout));
	uaddr2 = va_arg(args, __typeof__(uaddr2));
	val3 = va_arg(args, __typeof__(val3));

	return tsocks_libc_syscall(TSOCKS_NR_FUTEX, uaddr, op, val, timeout,
			uaddr2, val3);
}

/*
 * Handle accept4(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_accept4(va_list args)
{
	int sockfd;
	struct sockaddr *addr;
	socklen_t addrlen;
	int flags;

	sockfd = va_arg(args, __typeof__(sockfd));
	addr = va_arg(args, __typeof__(addr));
	addrlen = va_arg(args, __typeof__(addrlen));
	flags = va_arg(args, __typeof__(flags));

	return tsocks_accept4(sockfd, addr, &addrlen, flags);
}

/*
 * Handle epoll_create1(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_epoll_create1(va_list args)
{
	int flags;

	flags = va_arg(args, __typeof__(flags));

	return epoll_create1(flags);
}

/*
 * Handle epoll_wait(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_epoll_wait(va_list args)
{
	int epfd;
	struct epoll_event *events;
	int maxevents;
	int timeout;

	epfd = va_arg(args, __typeof__(epfd));
	events = va_arg(args, __typeof__(events));
	maxevents = va_arg(args, __typeof__(maxevents));
	timeout = va_arg(args, __typeof__(maxevents));

	return epoll_wait(epfd, events, maxevents, timeout);
}

/*
 * Handle epoll_pwait(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_epoll_pwait(va_list args)
{
	int epfd;
	struct epoll_event *events;
	int maxevents;
	int timeout;
	const sigset_t *sigmask;

	epfd = va_arg(args, __typeof__(epfd));
	events = va_arg(args, __typeof__(events));
	maxevents = va_arg(args, __typeof__(maxevents));
	timeout = va_arg(args, __typeof__(maxevents));
	sigmask = va_arg(args, __typeof__(sigmask));

	return epoll_pwait(epfd, events, maxevents, timeout, sigmask);
}

/*
 * Handle epoll_ctl(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_epoll_ctl(va_list args)
{
	int epfd;
	int op;
	int fd;
	struct epoll_event *event;

	epfd = va_arg(args, __typeof__(epfd));
	op = va_arg(args, __typeof__(op));
	fd = va_arg(args, __typeof__(fd));
	event = va_arg(args, __typeof__(event));

	return epoll_ctl(epfd, op, fd, event);
}

/*
 * Handle eventfd2(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_eventfd2(va_list args)
{
	unsigned int initval;
	int flags;

	initval = va_arg(args, __typeof__(initval));
	flags = va_arg(args, __typeof__(flags));

	return eventfd(initval, flags);
}

/*
 * Handle inotify_init1(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_inotify_init1(va_list args)
{
	int flags;
	flags = va_arg(args, __typeof__(flags));

	return inotify_init1(flags);
}

/*
 * Handle inotify_add_watch(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_inotify_add_watch(va_list args)
{
	int fd;
	const char *pathname;
	uint32_t mask;

	fd = va_arg(args, __typeof__(fd));
	pathname = va_arg(args, __typeof__(pathname));
	mask = va_arg(args, __typeof__(mask));

	return inotify_add_watch(fd, pathname, mask);
}

/*
 * Handle inotify_rm_watch(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_inotify_rm_watch(va_list args)
{
	int fd, wd;

	fd = va_arg(args, __typeof__(fd));
	wd = va_arg(args, __typeof__(wd));

	return inotify_rm_watch(fd, wd);
}

/*
 * Handle seccomp(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_seccomp(va_list args)
{
	unsigned int operation, flags;
	void *sargs;

	operation = va_arg(args, __typeof__(operation));
	flags = va_arg(args, __typeof__(flags));
	sargs = va_arg(args, __typeof__(sargs));

	return tsocks_libc_syscall(TSOCKS_NR_SECCOMP, operation, flags, sargs);
}

/*
 * Handle gettimeofday(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_gettimeofday(va_list args)
{
	struct timeval *tv;
	struct timezone *tz;

	tv = va_arg(args, __typeof__(tv));
	tz = va_arg(args, __typeof__(tz));

	return tsocks_libc_syscall(TSOCKS_NR_GETTIMEOFDAY, tv, tz);
}

/*
 * Handle clock_gettime(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_clock_gettime(va_list args)
{
	clockid_t clk_id;
	struct timespec *tp;

	clk_id = va_arg(args, __typeof__(clk_id));
	tp = va_arg(args, __typeof__(tp));

	return tsocks_libc_syscall(TSOCKS_NR_CLOCK_GETTIME, clk_id, tp);
}

/*
 * Handle fork(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_fork(void)
{
	return tsocks_libc_syscall(TSOCKS_NR_FORK);
}

/*
 * Handle memfd_create(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_memfd_create(va_list args)
{
	const char *name;
	unsigned int flags;

	name = va_arg(args, __typeof__(name));
	flags = va_arg(args, __typeof__(flags));

	return tsocks_libc_syscall(TSOCKS_NR_MEMFD_CREATE, name, flags);
}
/*
 * Handle getdents(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_getdents(va_list args)
{
	unsigned int fd;
	struct linux_dirent *dirp;
	unsigned int count;

	fd = va_arg(args, __typeof__(fd));
	dirp = va_arg(args, __typeof__(dirp));
	count = va_arg(args, __typeof__(count));

	return tsocks_libc_syscall(TSOCKS_NR_GETDENTS, fd, dirp, count);
}
/*
 * Handle getdents64(2) syscall.
 */
static LIBC_SYSCALL_RET_TYPE handle_getdents64(va_list args)
{
	unsigned int fd;
	struct linux_dirent64 *dirp;
	unsigned int count;

	fd = va_arg(args, __typeof__(fd));
	dirp = va_arg(args, __typeof__(dirp));
	count = va_arg(args, __typeof__(count));

	return tsocks_libc_syscall(TSOCKS_NR_GETDENTS64, fd, dirp, count);
}

#endif /* __linux__ */

/*
 * Torsocks call for syscall(2)
 */
LIBC_SYSCALL_RET_TYPE tsocks_syscall(long int number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;

	switch (number) {
	case TSOCKS_NR_SOCKET:
		ret = handle_socket(args);
		break;
	case TSOCKS_NR_CONNECT:
		ret = handle_connect(args);
		break;
	case TSOCKS_NR_CLOSE:
		ret = handle_close(args);
		break;
	case TSOCKS_NR_MMAP:
#if (defined(__NetBSD__) || defined(__FreeBSD__) || defined(__FreeBSD_kernel__)) && defined(__x86_64)
		/*
		 * On an 64 bit *BSD system, __syscall(2) should be used for mmap().
		 * This is NOT suppose to happen but for protection we deny that call.
		 */
		ret = -1;
		errno = ENOSYS;
#else
		/*
		 * The mmap/munmap syscall are handled here for a very specific case so
		 * buckle up here for the explanation :).
		 *
		 * Considering an application that handles its own memory using a
		 * malloc(2) hook for instance *AND* mmap() is called with syscall(),
		 * we have to route the call to the libc in order to complete the
		 * syscall() symbol lookup.
		 *
		 * The lookup process of the libdl (using dlsym(3)) calls at some point
		 * malloc for a temporary buffer so we end up in this torsocks wrapper
		 * when mmap() is called to create a new memory region for the
		 * application (remember the malloc hook). When getting here, the libc
		 * syscall() symbol is NOT yet populated because we are in the lookup
		 * code path. For this, we directly call mmap/munmap using the libc so
		 * the lookup can be completed.
		 *
		 * This crazy situation is present in Mozilla Firefox which handles its
		 * own memory using mmap() called by syscall(). Same for munmap().
		 */
		ret = handle_mmap(args);
#endif /* __NetBSD__, __FreeBSD__, __FreeBSD_kernel__, __x86_64 */
		break;
	case TSOCKS_NR_MUNMAP:
		ret = handle_munmap(args);
		break;
	case TSOCKS_NR_ACCEPT:
		ret = handle_accept(args);
		break;
	case TSOCKS_NR_GETPEERNAME:
		ret = handle_getpeername(args);
		break;
	case TSOCKS_NR_LISTEN:
		ret = handle_listen(args);
		break;
	case TSOCKS_NR_RECVMSG:
		ret = handle_recvmsg(args);
		break;
#if defined(__linux__)
	case TSOCKS_NR_GETTID:
		ret = handle_gettid();
		break;
	case TSOCKS_NR_GETRANDOM:
		ret = handle_getrandom(args);
		break;
	case TSOCKS_NR_FUTEX:
		ret = handle_futex(args);
		break;
	case TSOCKS_NR_ACCEPT4:
		ret = handle_accept4(args);
		break;
	case TSOCKS_NR_EPOLL_CREATE1:
		ret = handle_epoll_create1(args);
		break;
	case TSOCKS_NR_EPOLL_WAIT:
		ret = handle_epoll_wait(args);
		break;
	case TSOCKS_NR_EPOLL_PWAIT:
		ret = handle_epoll_pwait(args);
		break;
	case TSOCKS_NR_EPOLL_CTL:
		ret = handle_epoll_ctl(args);
		break;
	case TSOCKS_NR_EVENTFD2:
		ret = handle_eventfd2(args);
		break;
	case TSOCKS_NR_INOTIFY_INIT1:
		ret = handle_inotify_init1(args);
		break;
	case TSOCKS_NR_INOTIFY_ADD_WATCH:
		ret = handle_inotify_add_watch(args);
		break;
	case TSOCKS_NR_INOTIFY_RM_WATCH:
		ret = handle_inotify_rm_watch(args);
		break;
	case TSOCKS_NR_SCHED_GETAFFINITY:
		ret = handle_sched_getaffinity(args);
		break;
	case TSOCKS_NR_SECCOMP:
		ret = handle_seccomp(args);
		break;
	case TSOCKS_NR_GETTIMEOFDAY:
		ret = handle_gettimeofday(args);
		break;
	case TSOCKS_NR_CLOCK_GETTIME:
		ret = handle_clock_gettime(args);
		break;
	case TSOCKS_NR_FORK:
		ret = handle_fork();
		break;
	case TSOCKS_NR_MEMFD_CREATE:
		ret = handle_memfd_create(args);
		break;
	case TSOCKS_NR_GETDENTS:
		ret = handle_getdents(args);
		break;
	case TSOCKS_NR_GETDENTS64:
		ret = handle_getdents64(args);
		break;
#endif /* __linux__ */
	default:
		/*
		 * Because of the design of syscall(), we can't pass a va_list to it so
		 * we are constraint to use a whitelist scheme and denying the rest.
		 */
		WARN("[syscall] Unsupported syscall number %ld. Denying the call",
				number);
		ret = -1;
		errno = ENOSYS;
		break;
	}

	return ret;
}

/*
 * Libc hijacked symbol syscall(2).
 */
LIBC_SYSCALL_DECL
{
	LIBC_SYSCALL_RET_TYPE ret;
	va_list args;

	if (!tsocks_libc_syscall) {
		tsocks_initialize();
		tsocks_libc_syscall= tsocks_find_libc_symbol(
				LIBC_SYSCALL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	va_start(args, number);
	ret = tsocks_syscall(number, args);
	va_end(args);

	return ret;
}

/* Only used for *BSD systems. */
#if (defined(__NetBSD__) || defined(__FreeBSD__))

/* __syscall(2) */
TSOCKS_LIBC_DECL(__syscall, LIBC___SYSCALL_RET_TYPE, LIBC___SYSCALL_SIG)

/*
 * Handle *BSD mmap(2) syscall.
 */
static LIBC___SYSCALL_RET_TYPE handle_bsd_mmap(va_list args)
{
	void *addr;
	size_t len;
	int prot, flags, fd;
	off_t offset;

	addr = va_arg(args, __typeof__(addr));
	len = va_arg(args, __typeof__(len));
	prot = va_arg(args, __typeof__(prot));
	flags = va_arg(args, __typeof__(flags));
	fd = va_arg(args, __typeof__(fd));
	offset = va_arg(args, __typeof__(offset));

	return (LIBC___SYSCALL_RET_TYPE) mmap(addr, len, prot, flags, fd, offset);
}

LIBC___SYSCALL_RET_TYPE tsocks___syscall(quad_t number, va_list args)
{
	LIBC_SYSCALL_RET_TYPE ret;

	switch (number) {
	case TSOCKS_NR_MMAP:
		/*
		 * Please see the mmap comment in the syscall() function to understand
		 * why mmap is being hijacked.
		 */
		ret = handle_bsd_mmap(args);
		break;
	default:
		/*
		 * Because of the design of syscall(), we can't pass a va_list to it so
		 * we are constraint to use a whitelist scheme and denying the rest.
		 */
		WARN("[syscall] Unsupported __syscall number %ld. Denying the call",
				number);
		ret = -1;
		errno = ENOSYS;
		break;
	}

	return ret;
}

LIBC___SYSCALL_DECL
{
	LIBC___SYSCALL_RET_TYPE ret;
	va_list args;

	va_start(args, number);
	ret = tsocks___syscall(number, args);
	va_end(args);

	return ret;
}

#endif /* __NetBSD__, __FreeBSD__ */
